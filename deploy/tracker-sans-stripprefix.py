#!/usr/bin/env python3
"""Retire le stripprefix des routes qui servent le back-office /tracker.

    sudo python3 tracker-sans-stripprefix.py            # constate
    sudo python3 tracker-sans-stripprefix.py --ecrire   # repare

A RELANCER APRES TOUT CHANGEMENT DE DOMAINE SUR CETTE APPLICATION, pour la
meme raison que restaurer-priorites.py : Coolify regenere custom_labels et
remet un stripprefix sur chaque domaine porteur d un chemin.

Pourquoi /tracker doit garder son prefixe
-----------------------------------------
Pour /gate, le stripprefix est voulu : l application est montee aussi a la
racine. Le back-office, lui, est servi SOUS /tracker (ADMIN_BASE_PATH). Si
Traefik retire le prefixe, la requete arrive sur « / » et le visiteur tombe
sur le formulaire public de la porte a la place du tableau de bord — sans
erreur, ce qui rend la panne difficile a lire.

Ciblage par la REGLE, pas par le numero
---------------------------------------
La version precedente visait « https-5- » en dur. C etait juste le jour ou
elle a ete ecrite, mais les index sont attribues dans l ordre des domaines :
en ajouter un les decale, et le script serait alle decaper une autre route —
celles qui ont BESOIN de leur stripprefix. On repere donc les routeurs par
leur regle Traefik, seule chose qui dise vraiment ce qu ils servent.
"""
import argparse, base64, json, pathlib, re, urllib.error, urllib.request

API = "http://localhost:8000/api/v1"
APP = "qdj4xiwdvltpui9zjjgrm2zy"
CHEMIN = "/tracker"


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
                   help="retirer les stripprefix trouves (sinon, simple constat)")
    o = a.parse_args()

    app = api(f"/applications/{APP}", methode="GET")
    lignes = base64.b64decode(app["custom_labels"]).decode().splitlines()

    # Les routeurs dont la regle porte /tracker — http ET https.
    cibles = set()
    for l in lignes:
        m = re.match(r"traefik\.http\.routers\.([^.]+)\.rule=(.*)", l)
        if m and f"PathPrefix(`{CHEMIN}`)" in m.group(2):
            cibles.add(m.group(1))
    if not cibles:
        print(f"aucune route ne sert {CHEMIN} : rien a faire.")
        return
    print(f"routes servant {CHEMIN} : {sorted(cibles)}")

    sortie, retirees = [], []
    for l in lignes:
        # 1. la definition du middleware lui-meme
        if any(l.startswith(f"traefik.http.middlewares.{r}-stripprefix") for r in cibles):
            retirees.append(l.split("=")[0])
            continue
        # 2. sa mention dans la liste des middlewares du routeur
        m = re.match(r"traefik\.http\.routers\.([^.]+)\.middlewares=(.*)", l)
        if m and m.group(1) in cibles:
            gardes = [v for v in m.group(2).split(",") if "stripprefix" not in v]
            if len(gardes) != len(m.group(2).split(",")):
                retirees.append(f"{m.group(1)}.middlewares")
            l = f"traefik.http.routers.{m.group(1)}.middlewares=" + (",".join(gardes) or "gzip")
        sortie.append(l)

    if not retirees:
        print("aucun stripprefix sur ces routes : rien a faire.")
        return
    print(f"{len(retirees)} ligne(s) a corriger :")
    for r in retirees:
        print("  ", r)
    if not o.ecrire:
        print("\nRelancer avec --ecrire pour corriger.")
        return

    r = api(f"/applications/{APP}",
            {"custom_labels": base64.b64encode(("\n".join(sortie) + "\n").encode()).decode()},
            methode="PATCH")
    print("corrige :", "ok" if r in ({}, None) or "uuid" in r or "message" in r else r)
    print("Redeployer a la main pour publier.")


if __name__ == "__main__":
    main()
