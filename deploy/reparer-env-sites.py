#!/usr/bin/env python3
"""Remet dans Coolify la configuration des sites reellement servie par la porte.

    sudo python3 reparer-env-sites.py            # constate, n ecrit rien
    sudo python3 reparer-env-sites.py --ecrire   # repare

A quoi sert cet outil
---------------------
Coolify peut porter PLUSIEURS entrees d environnement de meme nom, et rien dans
son interface ne le montre. Le 2026-09-04, l application de la porte en avait
deux pour SITES_B64 et deux pour SITE_URLS_B64, toutes perimees (4 slugs), alors
que la porte en servait 35 : la configuration reelle ne vivait plus que dans
l environnement du conteneur en cours d execution.

C est un piege silencieux tant qu on ne redeploie pas. Au premier
redeploiement, la porte repart sur la valeur de Coolify — 31 sites perdent leur
onglet de tracker, et surtout leur protection : la porte laisse passer tout
visiteur d un slug qu elle ne connait pas (/gate/auth repond « chemin non
protege »). Les dossiers prives deviennent publics sans qu aucune alerte ne
parte.

Ce script compare les deux, et sait remettre la verite du conteneur dans
Coolify. Il ne redeploie jamais : on repare, on relit, on deploie a la main.

A lancer aussi en simple controle apres toute manipulation d environnement.
"""
import argparse, base64, json, pathlib, subprocess, sys, urllib.error, urllib.request

API = "http://localhost:8000/api/v1"
GATE_APP = "qdj4xiwdvltpui9zjjgrm2zy"
PLANCHER = 35
CLES = ("SITES_B64", "SITE_URLS_B64")


def api(chemin, charge=None, methode="POST"):
    jeton = pathlib.Path("/root/.coolify_token").read_text().strip()
    data = json.dumps(charge).encode() if charge is not None else None
    req = urllib.request.Request(
        API + chemin, data=data, method=methode,
        headers={"Authorization": "Bearer " + jeton, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            brut = r.read()
            return json.loads(brut) if brut else {}
    except urllib.error.HTTPError as e:
        return {"ERREUR": e.code, "corps": e.read().decode()[:200]}


def docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          check=True).stdout


def verite():
    """Ce que la porte sert vraiment, lu dans l environnement du conteneur."""
    noms = docker("ps", "--filter", f"name={GATE_APP}", "--format", "{{.Names}}").split()
    if not noms:
        sys.exit("aucun conteneur de la porte en ligne : rien de fiable a lire")
    env = docker("inspect", noms[0],
                 "--format", "{{range .Config.Env}}{{println .}}{{end}}")
    trouve = {}
    for cle in CLES:
        for ligne in env.splitlines():
            if ligne.startswith(cle + "="):
                trouve[cle] = json.loads(base64.b64decode(ligne[len(cle) + 1:]).decode())
    manquant = [c for c in CLES if c not in trouve]
    if manquant:
        sys.exit(f"absent de l environnement du conteneur : {manquant}")
    return noms[0], trouve


def main():
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument("--ecrire", action="store_true",
                   help="reecrire Coolify (sans ce drapeau, le script ne fait que constater)")
    o = a.parse_args()

    nom, vrai = verite()
    print(f"conteneur en ligne : {nom}")
    for cle in CLES:
        print(f"  {cle} : {len(vrai[cle])} slugs")
    if len(vrai["SITES_B64"]) < PLANCHER:
        sys.exit(f"REFUS : {len(vrai['SITES_B64'])} sites lus, {PLANCHER} attendus.")

    envs = api(f"/applications/{GATE_APP}/envs", methode="GET")
    ecart = False
    for cle in CLES:
        porteurs = [e for e in envs if e["key"] == cle]
        print(f"\nCoolify · {cle} : {len(porteurs)} entree(s)")
        for e in porteurs:
            try:
                n = len(json.loads(base64.b64decode(e.get("value") or "").decode()))
            except Exception:
                n = "illisible"
            drapeau = "" if n == len(vrai[cle]) else "   <-- ECART"
            print(f"    {e['uuid']} : {n} slugs{drapeau}")
        if len(porteurs) != 1 or porteurs and n != len(vrai[cle]):
            ecart = True

    if not ecart:
        print("\nCoolify est d accord avec le conteneur : rien a reparer.")
        return
    if not o.ecrire:
        print("\nECART CONSTATE. Relancer avec --ecrire pour remettre la verite du conteneur.")
        return

    for cle in CLES:
        for e in [x for x in envs if x["key"] == cle][1:]:
            api(f"/applications/{GATE_APP}/envs/{e['uuid']}", methode="DELETE")
            print(f"doublon supprime : {cle} ({e['uuid']})")
        val = base64.b64encode(json.dumps(vrai[cle]).encode()).decode()
        r = api(f"/applications/{GATE_APP}/envs", {"key": cle, "value": val}, methode="PATCH")
        ok = r in ({}, None) or "uuid" in r or "message" in r
        print(f"{cle} reecrit ({len(vrai[cle])} slugs) : {'ok' if ok else r}")

    envs = api(f"/applications/{GATE_APP}/envs", methode="GET")
    for cle in CLES:
        porteurs = [e for e in envs if e["key"] == cle]
        tailles = [len(json.loads(base64.b64decode(e.get("value") or "").decode()))
                   for e in porteurs]
        print(f"verification · {cle} : {len(porteurs)} entree(s), {tailles} slugs")
    print("\nRelire ci-dessus AVANT de redeployer : une entree par cle, "
          f"{len(vrai['SITES_B64'])} slugs.")


if __name__ == "__main__":
    main()
