# ac6000-ble

Pilote d'interopérabilité **non officiel** pour le chronographe airsoft
**Acetech AC6000-BT**, obtenu par rétro-ingénierie du protocole BLE (observation
du trafic Bluetooth + chaînes en clair de l'app). Permet de lire les tirs, la
table de munitions et de régler le grammage de bille, en Python (bleak) ou
directement dans Chrome (Web Bluetooth).

> ⚠️ **Projet non affilié à Acetech.** Marques et firmware appartiennent à leurs
> propriétaires. Réalisé pour l'interopérabilité avec mon propre matériel
> (France/UE : CPI art. L122-6-1 ; directive 2009/24/CE art. 6). Aucun code ni
> binaire de l'application d'origine n'est inclus ni redistribué.
>
> ⚠️ **Instrument de mesure.** Modifier le grammage change le calcul d'énergie
> (joules) affiché. N'utilise pas ces réglages pour contourner une vérification
> de conformité (limites de terrain). **Aucune garantie** — usage à tes risques.

Testé avec le firmware **1.017** (AC6000-BT5580). Un autre firmware peut différer.

## Fonctions

- Appairage applicatif rapide (jeton mémorisé, pas de ré-appairage à froid)
- Décodage des **tirs en direct** (m/s + fps)
- Lecture de la **table de munitions** (5 slots, poids de bille)
- **Écriture du grammage** d'un slot + re-sélection du slot actif
- Client **Python** (`ac6000_sniff.py`) et **Web Bluetooth** (`ac6000_web.html`)
- Parseur de captures PacketLogger (`tools/pklg_parse.py`)

## Installation (Python)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Utilisation (Python)

Chrono allumé, Bluetooth activé, application officielle **déconnectée**
(une seule connexion BLE à la fois).

```bash
# Scanner et lister les périphériques
python ac6000_sniff.py --scan-only

# Se connecter et logger les tirs en direct (m/s + fps)
python ac6000_sniff.py

# Lire la table de munitions
python ac6000_sniff.py --read-ammo

# Régler le poids d'un slot (grammes) + re-sélection auto
python ac6000_sniff.py --set-weight 3:0.25

# Sélectionner le slot de munition actif
python ac6000_sniff.py --select-slot 3
```

Pendant la capture live, tape la vitesse affichée sur le chrono + Entrée pour
poser un marqueur horodaté dans `ac6000_capture.jsonl`. `q` pour quitter.

## Utilisation (Chrome / Web Bluetooth)

`ac6000_web.html` tourne dans **Chrome ou Edge** (desktop ou Android). **Pas sur
iOS** (WebKit ne supporte pas Web Bluetooth). Contexte sécurisé requis :

```bash
python3 -m http.server 8000
# puis ouvrir http://localhost:8000/ac6000_web.html dans Chrome
```

Clique **Connecter**, choisis le `AC6000-BT…`, et utilise les boutons. Le jeton
d'appairage est mémorisé dans le `localStorage` du navigateur.

## Protocole

Résumé complet dans [PROTOCOLE.md](PROTOCOLE.md). En bref :

- Trame `AA | LEN | CMD | payload | CHECKSUM`, `CHECKSUM=(0x8B+somme(LEN..payload))&0xFF`
- Appairage : HELLO `0x4B` ↔ jeton de l'appareil ; obligatoire avant toute écriture
- Tir : `0x52` (spontané), vitesse = valeur16 LE / 100 m/s
- Munitions : lecture `0x47`, écriture poids `0x53` (g×100), sélection active `0x59`

## Tests

Tests du protocole (checksums, construction/analyse des trames) **sans matériel**,
validés contre des trames réelles capturées :

```bash
python test_protocol.py
```

## Analyser une capture PacketLogger

```bash
python tools/pklg_parse.py capture.pklg 0xe 0x12   # filtre sur les handles chrono
```
Auto-détecte l'endianness (captures macOS big-endian / iOS little-endian).

## Licence

MIT — voir [LICENSE](LICENSE).
