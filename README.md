![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Version](https://img.shields.io/badge/Version-1.1-orange.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Mac-lightgrey.svg)
![Downloads](https://img.shields.io/github/downloads/Orefie/Infos-configuration-router/total?style=flat-square&label=Téléchargements&color=blue)


# 📦 FULL_extraction_LB5

**Extraction complète et automatique de votre Livebox Orange en une seule commande !**

Extrait **TOUTES** les données de votre Livebox 5 (et modèles compatibles) pour remplacer votre box par un routeur tiers (Mikrotik, pfSense, etc.).

---

## 🎯 Objectif

Avant de remplacer votre Livebox par un routeur, vous devez récupérer :
- **Options DHCP IPv4** (60, 77, 90, 125) - Obligatoires pour l'authentification Orange
- **Options DHCPv6** (11, 15, 16, 17) - Nécessaires pour IPv6
- **Infos ONT/GPON** (serial, vendor, versions firmware)
- **Configuration réseau complète** (IP, MAC, DNS, etc.)

Ce script automatise **100% de l'extraction** en ~30 secondes avec **~97 appels API** !

---

## ✨ Fonctionnalités

### Données extraites :

✅ **DHCP IPv4/IPv6**
- Options 60, 77, 90, 125 (IPv4)
- Options 11, 15, 16, 17 (IPv6)
- Valeurs HEX prêtes pour Mikrotik

✅ **ONT/GPON**
- Numéro de série
- Vendor ID, Equipment ID
- Versions firmware (image0/image1)
- Débits downstream/upstream
- Puissance signal

✅ **Réseau**
- MAC Address Livebox
- IP publique IPv4/IPv6
- Gateway, DNS
- Préfixe IPv6 délégué (/56)

✅ **Configuration complète**
- WiFi (2.4G + 5G)
- Firewall & NAT
- Routing & QoS
- VoIP, IPTV, USB
- Et bien plus... (~97 endpoints API)

### Formats de sortie :

📄 **JSON brut** : `livebox_FULL_extraction_YYYYMMDD_HHMMSS.json`
- Toutes les données brutes de l'API
- Format machine-readable pour parsing/analyse

📖 **Rapport Markdown** : `livebox_RAPPORT_YYYYMMDD_HHMMSS.md`
- Rapport lisible formaté
- Tables et sections organisées
- Valeurs prêtes à copier/coller

---

## 📋 Prérequis

### Option 1 : Utiliser le script Python (recommandé)

- **Python 3.6+** installé
- Bibliothèque `requests`
- Connexion à la Livebox (Ethernet ou WiFi)

### Option 2 : Utiliser l'exécutable .exe (plus simple)

- **Aucun prérequis !**
- Le .exe est standalone (Python inclus)
- Fonctionne sur Windows 10/11

---

## 💻 Utilisation

### Étape 1 : Préparer la Livebox

⚠️ **IMPORTANT** : La Livebox **DOIT être connectée à Internet** pour que les options DHCP soient disponibles.

### Étape 2 : Lancer l'extraction

**Avec le script Python :**
```bash
python FULL_extraction_LB5_V1.0.py
```

**Avec l'exécutable :**
```bash
FULL_extraction_LB5.exe
```

**OU** double-cliquez sur le .exe

### Étape 3 : Saisir les informations

```
Adresse IP de la Livebox [192.168.1.1]:
```
→ Appuyez sur **Entrée** (défaut) ou tapez l'IP si modifiée

```
Mot de passe admin [admin]:
```
→ Appuyez sur **Entrée** (défaut) ou tapez votre mot de passe

### Étape 4 : Attendre l'extraction

```
EXTRACTION TOTALE EN COURS
══════════════════════════════════════════════════════════════════════
  [1/97] DeviceInfo.get... ✓
  [2/97] DeviceInfo.getDeviceLog... ✓
  [3/97] DeviceInfo.getDeviceCapabilities... ✓
  ...
  [97/97] PPP.Interface.get... ✓
```

⏱️ **Durée** : 20-60 secondes (~97 appels API)

### Étape 5 : Récupérer les fichiers

```
✨ EXTRACTION TERMINÉE
══════════════════════════════════════════════════════════════════════

📄 Fichier JSON brut : livebox_FULL_extraction_20260102_153045.json
📖 Rapport lisible   : livebox_RAPPORT_20260102_153045.md
```

**Ouvrez le fichier `.md`** pour voir toutes vos données formatées !

---

## 📖 Contenu du rapport Markdown

Le fichier `.md` généré contient :

### 📦 Informations appareil
- Modèle Livebox
- Numéro de série
- Version logicielle
- **MAC Address** (à cloner sur le routeur)

### 🌐 Statut WAN
- État connexion (O5_Operation = OK)
- IP publique IPv4/IPv6
- Gateway
- Préfixe IPv6 délégué

### 🔐 Options DHCP IPv4
```
Option 60 - Vendor Class Identifier
Valeur HEX : 736167656d
ASCII      : sagem
Mikrotik   : 0x736167656d

Option 77 - User Class
...

Option 90 - Authentication ⭐
Valeur HEX : 00000000000000000000001a0900000558...
Mikrotik   : 0x00000000000000000000001a0900000558...
```

### 🔐 Options DHCPv6
```
Option 11 - Authentication
Option 15 - User Class
Option 16 - Vendor Class
Option 17 - Vendor Specific
```

### 🔌 Informations ONT/GPON
- Serial Number
- Vendor ID (SMBS, HWTC, ALCL...)
- Hardware/Software versions
- Débits

### 📊 Résumé des appels API
- Tableau complet des 97 appels
- Statut (✅ OK / ❌ Erreur)

---

## 🔧 Dépannage

### Erreur "Échec authentification"

**Causes :**
- Mauvais mot de passe
- Mauvaise IP (vérifiez avec `ping 192.168.1.1`)
- Livebox éteinte

**Solution :**
```bash
# Tester la connexion
ping 192.168.1.1

# Vérifier l'IP de la Livebox
ipconfig  # Windows
ifconfig  # Linux/Mac
```

### Erreur "Options DHCP IPv4 manquantes"

**Cause :** La Livebox n'est **PAS connectée à Internet**

**Solution :**
1. Vérifier le voyant Internet sur la Livebox
2. Attendre 2-3 minutes après branchement de la fibre
3. Relancer le script

### Erreur "No module named 'requests'"

**Cause :** Dépendance manquante

**Solution :**
```bash
pip install -r requirements.txt
```

### Erreur "Python n'est pas reconnu..."

**Cause :** Python pas installé ou pas dans le PATH

**Solution :**
1. Télécharger Python : https://www.python.org/downloads/
2. **Cocher "Add Python to PATH"** pendant l'installation
3. Redémarrer le terminal

---

## 📚 Utilisation des données extraites

### Pour Mikrotik

Les valeurs sont **prêtes à copier/coller** dans RouterOS :

```routeros
/ip dhcp-client option
add code=60 name=vendor-class value=0x736167656d
add code=77 name=userclass value=0x2b46535644534c5f...
add code=90 name=authsend value=0x00000000000000000000001a...
```

### Pour pfSense / OPNsense

Les valeurs HEX peuvent être converties en base64 ou utilisées directement selon la config.

### Pour analyse / debugging

Le fichier JSON brut contient **TOUTES** les données retournées par l'API Livebox.

---

## ⚠️ Important - Sécurité

### Option 90 (Authentication)

⚠️ **CONFIDENTIEL - Ne pas partager publiquement !**

- Unique par Livebox
- Contient le FTI (Fiber Terminal Identifier)
- Hash d'authentification Orange
- **Nécessaire** pour connexion DHCP

### Partage des données

✅ **Vous pouvez partager** :
- Votre modèle Livebox
- Votre type de connexion (FSVDSL, etc.)
- Les problèmes rencontrés

❌ **NE PAS partager** :
- Option 90 complète
- MAC Address
- Numéro de série ONT
- IP publique

---

## 📊 Statistiques

- **97 appels API** différents
- **~30 secondes** d'extraction
- **2 fichiers** générés (JSON + Markdown)
- **Compatible** : Livebox 4, 5, 6

---

## 🛠️ Développement

### Structure du projet

```
FULL_extraction_LB5/
├── FULL_extraction_LB5_V1.0.py  # Script principal
├── requirements.txt              # Dépendances Python
├── make.bat                      # Script compilation .exe
├── README.md                     # Ce fichier
└── dist/                         # Dossier .exe (après compilation)
    └── FULL_extraction_LB5.exe
```

### Modifications

Le code est organisé en classes :

- `LiveboxFullExtractor` : Gestion API Livebox
  - `auth()` : Authentification
  - `call()` : Appel API générique
  - `extract_everything()` : Extraction complète

- `generate_readable_report()` : Génération rapport Markdown

### Ajouter des appels API

Éditez la liste `calls` dans `extract_everything()` :

```python
calls = [
    ...
    ("MonService", "maMethode", {"param": "valeur"}),
    ...
]
```

---

## 📜 Licence

**Open Source - Usage personnel**

Ce script est fourni tel quel, sans garantie.
Utilisation à vos propres risques.

---

## 🙏 Crédits

- **API Livebox** : Sagemcom
- **Communauté** : lafibre.info
- **Développement** : Claude Sonnet 4.5 (Anthropic)
- **Version** : 1.0 (2026-01-02)

---

## 🔗 Liens utiles

- [Forum lafibre.info - Remplacer Livebox](https://lafibre.info/remplacer-livebox/)
- [Guide Mikrotik complet](https://lafibre.info/remplacer-livebox/routeur-mikrotik-rb5009ugsin-pour-remplacer-livebox/)
- [Blog kveer.fr - Mikrotik Orange](https://blog.kveer.fr/posts/2025/01/remplacer-sa-livebox-par-un-routeur-mikrotik/)
- [GO-BOX (alternative)](https://github.com/Stoufiler/GO-BOX)

---

## 🆘 Support

Pour toute question ou problème :

1. **Lire ce README en entier** 📖
2. **Consulter le forum lafibre.info** 💬
3. **Vérifier les issues GitHub** (si applicable)

---

**🎯 Prêt à remplacer votre Livebox par un vrai routeur !** 🚀
