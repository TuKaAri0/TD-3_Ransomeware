# TD-03 : Ransomware - Gestion des Clés et Chiffrement

## Description

Projet académique développé dans le cadre du cours de cybersécurité portant sur la conception d'un ransomware éducatif en environnement de laboratoire.

**⚠️ AVERTISSEMENT : Ce projet est uniquement à des fins éducatives. L'utilisation de ce code à des fins malveillantes est illégale et strictement interdite.**

## Fonctionnalités

### ✅ Partie A : Vérification des Dépendances
- Vérification automatique de Python 3.8+
- Détection des bibliothèques `cryptography` et `paramiko`
- Installation automatique des dépendances manquantes
- Gestion complète des erreurs d'installation

### ✅ Partie B : Menu Principal
- Interface textuelle interactive avec options numérotées
- Validation robuste des saisies utilisateur
- Retour au menu principal après chaque opération
- Affichage clair des erreurs et des succès

### ✅ Partie C : Génération de Clés
- Support de plusieurs longueurs : 128, 192, 256 bits
- Algorithmes disponibles :
  - **AES** : Génération aléatoire sécurisée
  - **PBKDF2** : Dérivation de clé avec 100 000 itérations
- Stockage dans `/var/keys/` avec permissions 600 (rw-------)
- Format JSON avec métadonnées (timestamp, longueur, format)

### ✅ Partie D : Transfert SFTP
- Configuration interactive des paramètres de connexion
- Authentification par mot de passe ou clé SSH
- Création automatique des répertoires distants
- Vérification du succès du transfert
- Gestion complète des erreurs de connexion

### ✅ Partie E : Sélection et Chiffrement
- Sélection de fichiers individuels
- Sélection de dossiers entiers
- Chiffrement in-place (remplacement du fichier original)
- Mode de sauvegarde optionnel (.enc)
- Utilisation d'AES-CBC avec IV aléatoire

### ✅ Partie F : Fonctionnalités Avancées
- Chiffrement récursif des sous-dossiers
- Barre de progression pour les opérations longues
- Statistiques de chiffrement (succès/échecs)

## Prérequis

- **Python** : Version 3.8 ou supérieure
- **Système d'exploitation** : Linux ou Windows
- **Permissions** : Accès root/sudo recommandé pour écrire dans `/var/keys/`

## Installation

### 1. Cloner ou télécharger le projet

```bash
git clone <url-du-repo>
cd td3_chiffrement
```

### 2. Installer les dépendances

#### Méthode automatique (recommandée)
```bash
sudo python3 main.py
# Le programme vérifiera et proposera d'installer les dépendances manquantes
```

#### Méthode manuelle
```bash
pip install -r requirements.txt
```

## Utilisation

### Lancement du programme

```bash
sudo python3 main.py
```

**Note** : `sudo` est requis pour créer et écrire dans `/var/keys/`. Vous pouvez modifier la constante `KEYS_DIRECTORY` dans le code pour utiliser un autre répertoire.

### Menu principal

```
==================================================
          SYSTÈME DE CHIFFREMENT - TD3
==================================================

[1] Générer une nouvelle clé
[2] Envoyer une clé via SFTP
[3] Chiffrer des fichiers/dossiers
[4] Vérifier les dépendances
[5] Quitter

==================================================
```

## Exemples d'utilisation

### Exemple 1 : Génération de clé AES-256

```bash
[?] Votre choix : 1

Algorithme (1=AES, 2=PBKDF2) : 1
Longueur (1=128, 2=192, 3=256) : 3

[*] Clé AES-256 générée (32 octets)
[✓] Clé sauvegardée : /var/keys/key_aes_256_20260211_154230.json
[*] Permissions : 600 (rw-------)
```

### Exemple 2 : Transfert SFTP

```bash
[?] Votre choix : 2

[*] Fichiers de clés disponibles :
 [1] key_aes_256_20260211_154230.json (156 octets)

[?] Sélectionnez un fichier (1-1) : 1

 Hôte (IP ou domaine) : 192.168.1.100
 Port [22] : 22
 Nom d'utilisateur : kali

[*] Mode d'authentification :
 [1] Mot de passe
 [2] Clé SSH

[?] Choix (1-2) : 1
 Mot de passe : ********

[?] Chemin complet du fichier distant : ~/received_keys/cle.json

[✓] Connexion SSH établie
[✓] Session SFTP ouverte
[*] Transfert de /var/keys/key_aes_256_20260211_154230.json (156 octets)...
[✓] Transfert vérifié : 156 octets
[✓] Connexion fermée

[✓] SUCCÈS : Clé transférée vers 192.168.1.100:~/received_keys/cle.json
```

### Exemple 3 : Chiffrement de dossier

```bash
[?] Votre choix : 3

[*] Sélection de la clé de chiffrement :
 [1] key_aes_256_20260211_154230.json

[?] Sélectionnez une clé (1-1) : 1
[✓] Clé chargée : key_aes_256_20260211_154230.json

[*] Modes de sélection :
 [1] Fichier unique
 [2] Dossier complet
 [3] Chemin personnalisé

[?] Votre choix (1-3) : 2
[?] Chemin du dossier : /home/user/documents

[?] Chiffrement in-place (remplacement des fichiers originaux) ?
 Choix (O/N) : O

[*] Parcours récursif de /home/user/documents...
[*] 15 fichier(s) à chiffrer

[*] Chiffrement en cours...
[██████████████████████████████████████████████████] 100% (15/15)

[✓] SUCCÈS : Tous les fichiers ont été chiffrés (15/15)
```

## Architecture du projet

```
td3_chiffrement/
├── main.py              # Programme principal
├── requirements.txt     # Dépendances Python
└── README.md           # Documentation
```

## Fonctions principales

| Fonction | Description |
|----------|-------------|
| `check_dependencies()` | Vérifie et installe les dépendances |
| `generate_key(algo, length)` | Génère une clé de chiffrement |
| `save_key(key, path)` | Sauvegarde sécurisée d'une clé |
| `send_sftp(local, remote, config)` | Transfert SFTP sécurisé |
| `encrypt_file(filepath, key, inplace)` | Chiffre un fichier |
| `select_directories()` | Sélection interactive de fichiers |

## Sécurité

### Bonnes pratiques implémentées

- ✅ Génération de clés avec `secrets` (CSPRNG)
- ✅ Permissions restrictives sur les fichiers de clés (600)
- ✅ Vecteurs d'initialisation (IV) aléatoires pour chaque fichier
- ✅ Padding PKCS#7 pour AES-CBC
- ✅ Mots de passe non stockés en clair (getpass)
- ✅ Timeout sur les connexions réseau
- ✅ Gestion complète des exceptions

### Avertissements de sécurité

⚠️ **Ce code est destiné à des fins éducatives uniquement**
- Ne pas utiliser sur des systèmes de production
- Ne pas cibler des fichiers critiques du système
- Toujours tester dans une machine virtuelle isolée
- Conserver une sauvegarde avant tout test

## Compatibilité

### Systèmes d'exploitation
- ✅ Linux (testé sur Ubuntu, Debian, Kali)
- ✅ Windows 10/11
- ✅ macOS

### Versions Python testées
- Python 3.8
- Python 3.9
- Python 3.10
- Python 3.11
- Python 3.12

## Dépannage

### Erreur : Permission denied pour /var/keys/

**Solution** : Exécutez avec sudo ou modifiez la constante `KEYS_DIRECTORY` :
```python
KEYS_DIRECTORY = os.path.expanduser("~/.keys")  # Répertoire utilisateur
```

### Erreur : Module 'cryptography' not found

**Solution** : Installez manuellement :
```bash
pip install cryptography paramiko
```

### Erreur SFTP : Authentication failed

**Solutions** :
- Vérifiez les identifiants
- Testez la connexion SSH manuellement : `ssh user@host`
- Vérifiez que le serveur SSH est démarré
- Pour les clés SSH, vérifiez les permissions (600)


## Licence

Ce projet est uniquement à des fins éducatives. Toute utilisation à des fins malveillantes est strictement interdite et peut entraîner des poursuites judiciaires.

## Ressources

- [Documentation cryptography](https://cryptography.io/)
- [Documentation paramiko](https://www.paramiko.org/)
