# Protocole BLE — Acetech AC6000 (AC6000-BT)

Reconstitué par rétro-ingénierie de l'app AceSoft + 2 captures PacketLogger.
Aucune crypto : framing simple, vitesse en clair.

## GATT

| Rôle | Service UUID | Caractéristique UUID | Handle* | Propriétés |
|------|--------------|----------------------|---------|------------|
| NOTIFY (chrono → app) | `5cde0c3d-7b1d-4352-94bb-02269c9f42b5` | `3337e46e-f79e-4ff5-9a49-77c36d170c62` | 0x0d/0x0e | notify |
| WRITE (app → chrono)  | `53c47fe1-6c22-4ea6-99c7-7b6325ec75b9` | `9c6aa1ee-b4b9-44a1-ba45-1558c9109b4c` | 0x11/0x12 | write-without-response |

\* Les handles varient d'une session à l'autre ; se fier aux UUID.
Nom annoncé : `AC6000-BT<serie>` (ex. `AC6000-BT5580`).

## Framing

```
AA | LEN | CMD | payload... | CHECKSUM
```
- `AA` : octet de synchro (0xAA)
- `LEN` : longueur totale de la trame (AA et CHECKSUM compris)
- `CMD` : octet de commande
- `CHECKSUM = (0x8B + somme(LEN..dernier octet payload)) & 0xFF`
  (2 trames « info » — HELLO 0x4B et réponse série 0x49 — utilisent une
  variante `somme(AA..payload)&0xFF` ; sans importance si on rejoue les
  octets capturés.)

## Appairage / réveil (handshake applicatif, PAS de bonding OS)

```
app    → chrono : AA 06 4B 00 00 FB      HELLO (payload 00 00)
chrono → app    : AA 06 4B DF 02 DC      réponse, DF02 = jeton de l'appareil
```
Une fois appairé, l'app peut renvoyer directement le jeton (`AA 06 4B DF 02 DC`).
Après le HELLO, le chrono émet les tirs spontanément sur la caractéristique NOTIFY.
Le bonding BLE chiffré n'est pas requis (les notifications passent sans).

## Commandes observées

| CMD | Sens | Signification | Exemple |
|-----|------|---------------|---------|
| 0x4B | ↔ | HELLO / jeton | `aa064b0000fb` → `aa064bdf02dc` |
| 0x41 | ← | STATUS | `aa054100d1` |
| 0x62 | ↔ | Batterie | `aa056200f2` → `aa06620001f4` |
| 0x56 | ↔ | Version firmware (ASCII) | `aa055600e6` → `aa0956312e303137e1` = "1.017" |
| 0x49 | ↔ | Numéro de série (ASCII) | `aa0449d8` → `...3030303035353830...` = "00005580" |
| 0x5A | ↔ | Méta des records | `aa055a00ea` → `aa0a5a01035802190066` |
| 0x47 | ↔ | Lire un record stocké (groupe, index) | `aa06470101da` → `aa0b47003101580214007d` |
| 0x53 | → | Écrire un record munition (poids) | `aa0b5300410358021900a0` |
| 0x59 | → | **Sélectionner le slot de munition actif** | `aa06590103ee` (slot 3) |
| 0x52 | ← | **RAPPORT DE TIR (spontané)** | `aa0a520000cb000000b2` |

## Trame de tir 0x52 (la principale)

```
AA 0A 52 | 00 00 | VV VV | 00 00 | CS
          \_____/  \_____/
          réservé  vitesse (16 bits little-endian)
```
- **vitesse_m/s = valeur16 / 100**  (la valeur est en cm/s)
- **vitesse_fps = vitesse_m/s × 3.28084**  (conversion faite par l'app)

### Validation (2 captures indépendantes)

| Trame | valeur | m/s | fps | affiché |
|-------|--------|-----|-----|---------|
| `aa0a520000cb000000b2` | 203 | 2.03 | 6.7 | 6.6 fps / 2.03 m/s ✓ |
| `aa0a520000b100000098` | 177 | 1.77 | 5.8 | 5.8 fps / 1.77 m/s ✓ |
| `aa0a520000e5000000cc` | 229 | 2.29 | 7.5 | 7.5 fps / 2.29 m/s ✓ |
| `aa0a520000e1250000ed` | 9697 | 96.97 | 318 | (tir réel mai) |
| `aa0a520000492d00005d` | 11593 | 115.93 | 380 | (tir réel mai) |

## Table de munitions / poids de bille (calibre)

Le chrono stocke une table de types de munitions (slots 1..5), chacun avec un
**poids de bille**. Ce poids sert au calcul de l'énergie (Joule = ½·m·v²) ; il
ne change PAS la vitesse mesurée (0x52 reste en m/s bruts).

**Enregistrement (11 octets, commandes 0x47 lecture / 0x53 écriture) :**
```
AA 0B CMD | 00 | GG | SS | F2 F2 | WW WW | CS
                  │    │    └(LE)  └(LE) poids de bille = grammes × 100
                  │    └ slot de munition (1..5)
                  └ groupe/profil (ASCII, 'A'=0x41 ici ; '0'/'1' selon le mode)
          F2 = champ secondaire 16b LE (600 dans la capture, non modifié)
```

**Lecture d'un slot** : `AA 06 47 | GRP SS | CS`  (ex. `aa06470101da` = grp 1, slot 1)
→ réponse 0x47 de 11 octets ci-dessus.

**Écriture du poids (changement de calibre)** : commande **0x53**, même structure,
confirmée par un `STATUS 0x41` (`aa054100d1`). Exemples réels de la capture :

| Trame 0x53 | slot | poids |
|---|---|---|
| `aa0b5300410558021c00a5` | 5 | 0,28 g |
| `aa0b5300410458021800a0` | 4 | 0,24 g |
| `aa0b53004103580214009b` | 3 | 0,20 g |

Encodage du poids : `grammes × 100`, 16 bits little-endian (0.20 g → `14 00`,
0.25 g → `19 00`, 0.28 g → `1c 00`, 0.32 g → `20 00`, 0.40 g → `28 00`).

Pour modifier proprement, l'app fait **lecture → modification → réécriture** :
elle lit le slot (0x47), reprend `GG` et `F2` de la réponse, et ne change que le
champ poids avant de renvoyer un 0x53. Le script fait pareil.

**Sélection du slot actif (commande 0x59)** : écrire le poids (0x53) ne suffit
PAS à ce que le chrono applique le slot sur son écran. Il faut **re-sélectionner**
le slot actif avec `0x59` : `AA 06 59 | GG SS | CS` (GG=groupe `01`, SS=slot).
Comme le device n'actualise que sur un *changement* de sélection, on sélectionne
un autre slot puis on revient sur la cible :
```
aa06590101ec   SELECT slot 1
aa06590103ee   SELECT slot 3   (retour sur la cible → poids appliqué)
```
Chaque 0x59 est acquitté par `STATUS 0x41`. Le jeton d'appairage (df02) doit être
reçu avant toute écriture 0x53/0x59, sinon elles sont ignorées.

## Binaire de l'app

`/Applications/AceSoft.app` (app iOS native Apple Silicon). Binaire chiffré
FairPlay sur **une seule page de 4 Ko** (la routine de conversion fps/J, non
nécessaire : la vitesse arrive déjà décodée). Reste en clair : UUID, noms de
commandes, chemins source Swift (`SpeedTestViewController.swift`, etc.),
RxBluetoothKit.
