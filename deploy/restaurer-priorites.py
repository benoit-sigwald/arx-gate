#!/usr/bin/env python3
"""Remet priority=300 sur toutes les routes Traefik de la porte.

    sudo python3 restaurer-priorites.py            # constate
    sudo python3 restaurer-priorites.py --ecrire   # repare

A RELANCER APRES TOUT CHANGEMENT DE DOMAINE SUR CETTE APPLICATION.

Coolify REGENERE custom_labels des qu on modifie `domains`. Les priorites
posees a la main disparaissent alors en silence, et arxweb — dont la regle
Traefik est plus longue, donc prioritaire a egalite — reprend /gate sur
arx-consulting.com. La porte cesse de repondre sans qu aucune erreur ne soit
levee : c est le site voisin qui sert le chemin.

Le script est idempotent : sans priorite manquante, il ne touche a rien.
Il ne redeploie jamais — on ecrit, on relit, on deploie a la main.
"""
import argparse, base64, json, pathlib, urllib.error, urllib.request

API = "http://localhost:8000/api/v1"
APP = "qdj4xiwdvltpui9zjjgrm2zy"
PRIORITE = 300


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
        return {"ERREUR": e.code, "corps": e.read().decode()[:300]}


def main():
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument("--ecrire", action="store_true",
                   help="ajouter les priorites manquantes (sinon, simple constat)")
    o = a.parse_args()

    app = api(f"/applications/{APP}", methode="GET")
    labels = base64.b64decode(app["custom_labels"]).decode().rstrip("\n")
    routeurs = sorted({l.split(".")[3] for l in labels.splitlines()
                       if l.startswith("traefik.http.routers.")})
    attendue = "traefik.http.routers.{}.priority=" + str(PRIORITE)
    manquantes = [attendue.format(r) for r in routeurs if attendue.format(r) not in labels]

    print(f"{len(routeurs)} routeurs, {len(routeurs) - len(manquantes)} en priority={PRIORITE}")
    if not manquantes:
        print("rien a faire.")
        return
    for l in manquantes:
        print("  manquante :", l.split(".")[3])
    if not o.ecrire:
        print("\nRelancer avec --ecrire pour les ajouter.")
        return

    nouveaux = labels + "\n" + "\n".join(manquantes) + "\n"
    r = api(f"/applications/{APP}",
            {"custom_labels": base64.b64encode(nouveaux.encode()).decode()}, methode="PATCH")
    print(f"{len(manquantes)} priorite(s) ajoutee(s) :",
          "ok" if r in ({}, None) or "uuid" in r or "message" in r else r)
    print("Redeployer a la main pour publier.")


if __name__ == "__main__":
    main()
