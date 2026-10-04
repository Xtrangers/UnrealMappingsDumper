# Fiche technique — UnrealMappingsDumper.dll (UMD)

| Champ | Valeur |
|---|---|
| **Nom binaire** | `UnrealMappingsDumper.dll` |
| **Nom projet** | `UnrealMappingsDumper` |
| **Statut** | 🟢 Prod critique (dumper usmap Aion 2) |
| **Famille** | Dumper UE (prod) |
| **Fork de** | OutTheShade/UnrealMappingsDumper (upstream TheNaeem) |
| **Dépôt GitHub** | https://github.com/Xtrangers/UnrealMappingsDumper (privé) |
| **Repo local** | `C:\IA\Claude\Game-Tools\Dll\projet\UnrealMappingsDumper\` |
| **Binaire déployé** | `C:\IA\Claude\Game-Tools\Dll\bin\UnrealMappingsDumper.dll` |
| **Langage** | C++23 |
| **Compilateur** | MSVC (Visual Studio 2022) via `.sln` |
| **Architecture** | x64 |
| **Jeu cible** | Aion 2 (UE 5.3.2 custom NCsoft) + autres jeux UE |
| **Compatible NCGuard** | 🟢 Oui (Manual Mapping APC-dispatch, pattern thread pool) |

## Format de sortie

- `.usmap v3 custom` **non-standard** (header 13 B SANS `bHasVersioning`).
- Nécessite **notre parseur custom** (`extract_names.py` dans scratchpad,
  USMAP Explorer, Aion2PacketTools).
- Incompatible CUE4Parse upstream direct.
- 100 % couverture typage sur Enum/Array/Set/Map/Byte/Optional
  (depuis v0.4 détection dynamique + FOptionalProperty).

## Dépôts

- **origin** : `Xtrangers/UnrealMappingsDumper` (notre fork prod)
- **upstream** : `TheNaeem/UnrealMappingsDumper` (fork originel)

## Interactions avec le projet

- **Lancé par** : SysUtil onglet Session (injection Manual Mapping).
- **Lit** : `C:\Users\Public\offsets-aion2.json` (produit par OffsetFinder).
- **Écrit** : `C:\Users\Public\testscan.log` + usmap final.
- **Consommé par** : USMAP Explorer (Aion2OUTILS), AIONSERVER
  (Aion2PacketTools), AION2-STUDIO.

## Détections dynamiques (04/10/2026)

| Détection | Fonction | Valeur Aion 2 |
|---|---|---|
| `FPropertySize` | `TryDetectFPropertySize` | 0x70 (OptimizedFName) |
| `ArrayInnerExtraOffset` | `TryDetectArrayInnerOffset` | 8 (UE 5.3+ reorder) |
| `FSetProperty` | nouveau class séparé | Inner à FPropertySize+0 |
| `FOptionalProperty` | nouveau class | ValueProperty à FPropertySize+0 |

Plus aucun hardcoding d'offset UE dans UMD.

## À faire / idées

- Resynchronisation du fork avec upstream TheNaeem (pulls réguliers).
- Automatisation de la détection pour d'autres jeux UE custom (pattern
  « OptimizedFName style Fortnite »).
