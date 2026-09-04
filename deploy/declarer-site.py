#!/usr/bin/env python3
"""Declare un site dans la porte : SITES_B64, SITE_URLS_B64, puis redeploiement.

    sudo python3 declarer-site.py capgrowth GATE_CAPGROWTH \\
        https://arx-consulting.com/capgrowth/ /root/.gate_capgrowth_pw

Sans cette declaration, le site n existe pas pour la porte : il n a pas
d onglet dans le tracker, et le beacon rejette ses visites (« if (!site)
return »). Pour un site protege, c est pire — /gate/auth?site=<slug> repond
200 « chemin non protege » et laisse passer tout le monde.

LA SOURCE DE VERITE EST LE CONTENEUR, PAS L API COOLIFY
-------------------------------------------------------
Le 2026-09-04, declarer capgrowth en relisant SITES_B64 par l API a rendu
« sites : 4 -> 5 » alors que la porte en servait 35. Coolify portait DEUX
entrees SITES_B64 concurrentes, toutes deux perimees ; la configuration reelle
ne vivait que dans l environnement du conteneur en cours d execution. Ecrire ce
que rend l API aurait publie une configuration amputee de 31 sites, et rendu
les dossiers prives accessibles a tous.

Ce script lit donc l environnement du conteneur, refuse d ecrire s il y trouve
moins de sites qu attendu, et supprime les entrees en double avant d ecrire —
deux entrees de meme nom rendent tout ecrasement imprevisible.
"""
import argparse, base64, json, pathlib, subprocess, sys, urllib.error, urllib.request

API = "http://localhost:8000/api/v1"
GATE_APP = "qdj4xiwdvltpui9zjjgrm2zy"
PLANCHER = 35  # en dessous, on refuse : la lecture est suspecte, pas le parc
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


def conteneur():
    """Le conteneur de la porte actuellement en ligne."""
    noms = subprocess.run(
        ["docker", "ps", "--filter", f"name={GATE_APP}", "--format", "{{.Names}}"],
        capture_output=True, text=True, check=True).stdout.split()
    if not noms:
        sys.exit("aucun conteneur de la porte en ligne : rien de fiable a lire")
    return noms[0]


def lire_verite(nom, cle):
    """La valeur reellement servie, prise dans l environnement du conteneur."""
    env = subprocess.run(
        ["docker", "inspect", nom, "--format", "{{range .Config.Env}}{{println .}}{{end}}"],
        capture_output=True, text=True, check=True).stdout
    for ligne in env.splitlines():
        if ligne.startswith(cle + "="):
            return json.loads(base64.b64decode(ligne[len(cle) + 1:]).decode())
    sys.exit(f"{cle} absent de l environnement du conteneur")


def main():
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument("slug"); a.add_argument("ora_user"); a.add_argument("url")
    a.add_argument("fichier_mdp", help="fichier contenant le mot de passe du schema")
    a.add_argument("--redeployer", action="store_true",
                   help="redeployer la porte apres verification")
    o = a.parse_args()

    nom = conteneur()
    sites = lire_verite(nom, "SITES_B64")
    urls = lire_verite(nom, "SITE_URLS_B64")
    print(f"source de verite ({nom}) : {len(sites)} sites, {len(urls)} URLs")
    if len(sites) < PLANCHER:
        sys.exit(f"REFUS : {len(sites)} sites lus, {PLANCHER} attendus au minimum.\n"
                 "Ecrire maintenant amputerait la configuration. Verifier a la main.")

    sites[o.slug] = {"user": o.ora_user,
                     "password": pathlib.Path(o.fichier_mdp).read_text().strip()}
    urls[o.slug] = o.url
    voulu = {c: base64.b64encode(json.dumps(v).encode()).decode()
             for c, v in (("SITES_B64", sites), ("SITE_URLS_B64", urls))}

    envs = api(f"/applications/{GATE_APP}/envs", methode="GET")
    for cle in CLES:
        for e in [x for x in envs if x["key"] == cle][1:]:
            api(f"/applications/{GATE_APP}/envs/{e['uuid']}", methode="DELETE")
            print(f"  doublon supprime : {cle} ({e['uuid']})")

    for cle, val in voulu.items():
        r = api(f"/applications/{GATE_APP}/envs", {"key": cle, "value": val}, methode="PATCH")
        ok = r in ({}, None) or "uuid" in r or "message" in r
        print(f"{cle} ecrit ({len(val)} car.) : {'ok' if ok else r}")

    # On relit par l API : c est elle qui servira au prochain deploiement.
    envs = api(f"/applications/{GATE_APP}/envs", methode="GET")
    for cle in CLES:
        porteurs = [e for e in envs if e["key"] == cle]
        tailles = [len(json.loads(base64.b64decode(e.get("value") or "").decode()))
                   for e in porteurs]
        print(f"{cle} : {len(porteurs)} entree(s), {tailles} slugs")
        if len(porteurs) != 1 or tailles != [len(sites)]:
            sys.exit("REFUS de redeployer : l API ne rend pas ce qui vient d etre ecrit.")

    # Un slug sans URL n est pas inoffensif : siteUrl() retombe alors sur
    # arx-sites.duckdns.org/<slug>/, qui n existe pas. Le lien « ouvrir » du
    # tracker mene a une 404, et on croit le site casse.
    sans_url = sorted(s for s in sites if s not in urls)
    if sans_url:
        print(f"ATTENTION — slugs sans URL declaree : {sans_url}")

    print(f"\n{o.slug} declare. {len(sites)} sites.")
    if o.redeployer:
        print("redeploiement :",
              json.dumps(api(f"/deploy?uuid={GATE_APP}&force=true", {}))[:130])
    else:
        print("relancer avec --redeployer pour publier.")


if __name__ == "__main__":
    main()
