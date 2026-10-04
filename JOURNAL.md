# JOURNAL — UnrealMappingsDumper (UMD)

Fiche compagnon locale au repo. Le README.md d'origine du projet reste
la référence pour l'usage général. Ce JOURNAL trace les versions
custom patchées Aion 2.

Journal anti-chronologique.

---

## 2026-10-04 — Migration dans Game-Tools/Dll/projet/

Déplacement du dossier `C:\IA\Claude\Game-Tools\UnrealMappingsDumper\`
vers `C:\IA\Claude\Game-Tools\Dll\projet\UnrealMappingsDumper\` dans
le cadre du chantier Dll/ migration 03→04/10/2026.

- Dépôt distant `Xtrangers/UnrealMappingsDumper` INCHANGÉ.
- `.git` local porte toujours origin + upstream (TheNaeem fork originel).
- Ajout d'un `JOURNAL.md` compagnon + `fiche-dll.md`.
- Pas de modification du code source.

---

## 2026-10-04 (02h) — v0.4 détection dynamique complète

Dernier commit `ad853fd` sur `master` : ajout support FOptionalProperty
UE 5.3 (TOptional<T>). COURANT v11 validé par AIONSERVER 818/818 tests.

Détection dynamique complète :
- `FPropertySize` détecté auto (= 0x70 pour Aion 2 OptimizedFName NCsoft).
- `ArrayInnerExtraOffset` détecté auto (= 8 pour UE 5.3+ reorder).
- `FSetProperty` séparé (Inner à FPropertySize+0).
- `FOptionalProperty` ajouté (position EPropertyType=28).

Logs runtime dans `C:\Users\Public\umd-fproperty-detect.log`.

---

## 2026-10-03 — Refonte CLIENT/ + Shell COM autonome

Commit `1f8c621` : UMD lit la version du client via Shell COM
(`PKEY_Software_ProductVersion`, GUID
`0CEF7D53-FA64-11D1-A203-0000F81FEDEE` pid 8) directement, règle
d'autonomie absolue (pas de fichier side partagé avec SysUtil).

---

## Antérieur à 2026-10

Historique complet dans `git log` sur master.
