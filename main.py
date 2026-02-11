import sys
import subprocess
import importlib.util
import os
import json
from datetime import datetime
from pathlib import Path

# Configuration des dépendances requises
REQUIRED_PYTHON = (3, 8)
REQUIRED_PACKAGES = {
    "cryptography": "cryptography",
    "paramiko": "paramiko"
}

# Configuration des chemins
KEYS_DIRECTORY = "/var/keys"

def check_python_version():

    current_version = sys.version_info
    print(f"[*] Vérification de la version Python...")

    if current_version < REQUIRED_PYTHON:
        print(f"    [✗] ERREUR : Python {REQUIRED_PYTHON[0]}.{REQUIRED_PYTHON[1]}+ requis")
        print(f"    [!] Version actuelle : {current_version.major}.{current_version.minor}.{current_version.micro}")
        return False

    print(f"    [✓] Python {current_version.major}.{current_version.minor}.{current_version.micro} détecté")
    return True


def is_package_installed(package_name):
    """
    Vérifie si un package Python est installé

    Args:
        package_name (str): Nom du package à vérifier

    Returns:
        bool: True si installé, False sinon
    """
    spec = importlib.util.find_spec(package_name)
    return spec is not None


def install_package(package_name):
    """
    Installe un package Python via pip

    Args:
        package_name (str): Nom du package à installer

    Returns:
        bool: True si installation réussie, False sinon
    """
    print(f"    [*] Installation de {package_name}...")

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", package_name, "--quiet"],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode == 0:
            print(f"    [✓] {package_name} installé avec succès")
            return True
        else:
            print(f"    [✗] Échec d'installation de {package_name}")
            if result.stderr:
                print(f"    [!] Détails : {result.stderr.strip()}")
            return False

    except subprocess.TimeoutExpired:
        print(f"    [✗] Timeout lors de l'installation de {package_name}")
        return False
    except Exception as e:
        print(f"    [✗] Erreur lors de l'installation de {package_name}")
        print(f"    [!] Exception : {str(e)}")
        return False


def check_dependencies():

    print("\n" + "=" * 50)
    print("VÉRIFICATION DES DÉPENDANCES")
    print("=" * 50 + "\n")

    if not check_python_version():
        print("\n[!] Veuillez installer Python 3.8 ou supérieur")
        print("[!] Téléchargement : https://www.python.org/downloads/\n")
        return False

    print()

    print("[*] Vérification des bibliothèques Python...")
    missing_packages = []

    for package_name, pip_name in REQUIRED_PACKAGES.items():
        if is_package_installed(package_name):
            print(f"    [✓] {package_name} est installé")
        else:
            print(f"    [✗] {package_name} est manquant")
            missing_packages.append((package_name, pip_name))

    if not missing_packages:
        print("\n" + "=" * 50)
        print("[✓] TOUTES LES DÉPENDANCES SONT SATISFAITES")
        print("=" * 50 + "\n")
        return True

    print(f"\n[!] {len(missing_packages)} dépendance(s) manquante(s)")
    print("[?] Voulez-vous les installer automatiquement ?")

    while True:
        choice = input("    Choix (O/N) : ").strip().upper()
        if choice in ['O', 'N']:
            break
        print("    [!] Veuillez saisir 'O' pour Oui ou 'N' pour Non")

    if choice == 'N':
        print("\n[!] Installation annulée par l'utilisateur")
        print("[!] Installation manuelle requise :")
        for _, pip_name in missing_packages:
            print(f"    pip install {pip_name}")
        print()
        return False

    print("\n[*] Début de l'installation automatique...\n")

    installation_results = []
    for package_name, pip_name in missing_packages:
        success = install_package(pip_name)
        installation_results.append((package_name, success))

    print("\n" + "=" * 50)
    print("BILAN DE L'INSTALLATION")
    print("=" * 50)

    all_success = all(success for _, success in installation_results)

    if all_success:
        print("[✓] Toutes les dépendances ont été installées avec succès")
        print("=" * 50 + "\n")
        return True
    else:
        print("[✗] Certaines installations ont échoué :")
        for package_name, success in installation_results:
            status = "[✓]" if success else "[✗]"
            print(f"    {status} {package_name}")
        print("\n[!] Veuillez installer manuellement les dépendances manquantes")
        print("=" * 50 + "\n")
        return False

def generate_key(algo, length):
    """
    Génère une clé de chiffrement selon l'algorithme et la longueur spécifiés

    Args:
        algo (str): Algorithme de génération ('AES' ou 'PBKDF2')
        length (int): Longueur de la clé en bits (128, 192, 256)

    Returns:
        bytes: Clé générée ou None en cas d'erreur
    """
    try:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        import secrets

        # Conversion de bits en octets
        key_size = length // 8

        if algo.upper() == "AES":
            # Génération aléatoire sécurisée pour AES
            key = secrets.token_bytes(key_size)
            print(f"[*] Clé AES-{length} générée ({key_size} octets)")
            return key

        elif algo.upper() == "PBKDF2":
            # Génération avec PBKDF2
            password = secrets.token_bytes(32)  # Mot de passe aléatoire
            salt = secrets.token_bytes(16)  # Salt aléatoire

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=key_size,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )

            key = kdf.derive(password)
            print(f"[*] Clé PBKDF2-{length} générée ({key_size} octets)")
            return key

        else:
            print(f"[✗] Algorithme inconnu : {algo}")
            return None

    except ImportError:
        print("[✗] Bibliothèque cryptography non disponible")
        return None
    except Exception as e:
        print(f"[✗] Erreur lors de la génération de clé : {str(e)}")
        return None


def save_key(key, path):
    """
    Sauvegarde une clé de chiffrement de manière sécurisée

    Args:
        key (bytes): Clé à sauvegarder
        path (str): Chemin complet du fichier de destination

    Returns:
        bool: True si sauvegarde réussie, False sinon
    """
    try:
        import base64

        # Création du répertoire si nécessaire
        directory = os.path.dirname(path)
        if not os.path.exists(directory):
            os.makedirs(directory, mode=0o700, exist_ok=True)
            print(f"[*] Répertoire créé : {directory}")

        # Préparation des données à sauvegarder
        key_data = {
            "key": base64.b64encode(key).decode('utf-8'),
            "length": len(key) * 8,
            "created_at": datetime.now().isoformat(),
            "format": "base64"
        }

        # Écriture du fichier avec permissions restreintes
        with open(path, 'w') as f:
            json.dump(key_data, f, indent=4)

        # Application des permissions restrictives (lecture/écriture propriétaire uniquement)
        os.chmod(path, 0o600)

        print(f"[✓] Clé sauvegardée : {path}")
        print(f"[*] Permissions : 600 (rw-------)")
        return True

    except PermissionError:
        print(f"[✗] Permission refusée pour écrire dans : {path}")
        print(f"[!] Essayez d'exécuter avec sudo ou modifiez KEYS_DIRECTORY")
        return False
    except Exception as e:
        print(f"[✗] Erreur lors de la sauvegarde : {str(e)}")
        return False


def generer_cle():
    """
    Interface utilisateur pour la génération de clés
    Partie C du TD
    """
    print("\n" + "-" * 50)
    print("GÉNÉRATION DE CLÉ DE CHIFFREMENT")
    print("-" * 50 + "\n")

    # Sélection de l'algorithme
    print("[*] Algorithmes disponibles :")
    print("    [1] AES (Advanced Encryption Standard)")
    print("    [2] PBKDF2 (Password-Based Key Derivation Function 2)")

    while True:
        choix_algo = input("\n[?] Choix de l'algorithme (1-2) : ").strip()
        if choix_algo in ['1', '2']:
            algo = "AES" if choix_algo == '1' else "PBKDF2"
            break
        print("[✗] Veuillez choisir 1 ou 2")

    # Sélection de la longueur
    print(f"\n[*] Longueurs disponibles pour {algo} :")
    print("    [1] 128 bits")
    print("    [2] 192 bits")
    print("    [3] 256 bits")

    while True:
        choix_length = input("\n[?] Choix de la longueur (1-3) : ").strip()
        if choix_length in ['1', '2', '3']:
            lengths = {1: 128, 2: 192, 3: 256}
            length = lengths[int(choix_length)]
            break
        print("[✗] Veuillez choisir 1, 2 ou 3")

    # Génération de la clé
    print(f"\n[*] Génération d'une clé {algo}-{length}...")
    key = generate_key(algo, length)

    if key is None:
        afficher_erreur("Échec de la génération de clé")
        return

    # Création du nom de fichier
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"key_{algo.lower()}_{length}_{timestamp}.json"
    filepath = os.path.join(KEYS_DIRECTORY, filename)

    # Sauvegarde de la clé
    print(f"\n[*] Sauvegarde de la clé...")
    if save_key(key, filepath):
        afficher_succes(f"Clé générée et sauvegardée : {filepath}")
    else:
        afficher_erreur("Échec de la sauvegarde de la clé")


def send_sftp(local, remote, config):
    """
    Transfère un fichier vers un serveur distant via SFTP

    Args:
        local (str): Chemin du fichier local
        remote (str): Chemin de destination sur le serveur
        config (dict): Configuration SFTP (host, port, username, password/key)

    Returns:
        bool: True si transfert réussi, False sinon
    """
    try:
        import paramiko
        from paramiko import SSHClient, AutoAddPolicy

        print(f"[*] Connexion à {config['host']}:{config['port']}...")

        # Création du client SSH
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())

        # Connexion au serveur
        connect_kwargs = {
            'hostname': config['host'],
            'port': config['port'],
            'username': config['username'],
            'timeout': 30
        }

        # Authentification par mot de passe ou clé
        if 'password' in config and config['password']:
            connect_kwargs['password'] = config['password']
        elif 'key_filename' in config and config['key_filename']:
            connect_kwargs['key_filename'] = config['key_filename']

        ssh.connect(**connect_kwargs)
        print("[✓] Connexion SSH établie")

        # Ouverture de la session SFTP
        sftp = ssh.open_sftp()
        print("[✓] Session SFTP ouverte")

        # Vérification du fichier local
        if not os.path.exists(local):
            print(f"[✗] Fichier local introuvable : {local}")
            sftp.close()
            ssh.close()
            return False

        # Transfert du fichier
        file_size = os.path.getsize(local)
        print(f"[*] Transfert de {local} ({file_size} octets)...")

        sftp.put(local, remote)

        # Vérification du transfert
        try:
            remote_stat = sftp.stat(remote)
            if remote_stat.st_size == file_size:
                print(f"[✓] Transfert vérifié : {remote_stat.st_size} octets")
                success = True
            else:
                print(f"[✗] Taille incorrecte sur le serveur")
                success = False
        except:
            print("[!] Impossible de vérifier le transfert")
            success = True  # On considère le transfert réussi si pas d'erreur

        # Fermeture des connexions
        sftp.close()
        ssh.close()
        print("[✓] Connexion fermée")

        return success

    except paramiko.AuthenticationException:
        print("[✗] Erreur d'authentification")
        return False
    except paramiko.SSHException as e:
        print(f"[✗] Erreur SSH : {str(e)}")
        return False
    except Exception as e:
        print(f"[✗] Erreur lors du transfert : {str(e)}")
        return False


def envoyer_cle_sftp():
    """
    Interface utilisateur pour le transfert SFTP
    Partie D du TD
    """
    print("\n" + "-" * 50)
    print("TRANSFERT SFTP DE CLÉ")
    print("-" * 50 + "\n")

    # Sélection du fichier local
    print("[*] Fichiers de clés disponibles :")

    try:
        if os.path.exists(KEYS_DIRECTORY):
            key_files = [f for f in os.listdir(KEYS_DIRECTORY) if f.endswith('.json')]

            if not key_files:
                afficher_erreur("Aucun fichier de clé trouvé")
                print(f"[!] Générez d'abord une clé (option 1)")
                return

            for idx, filename in enumerate(key_files, 1):
                filepath = os.path.join(KEYS_DIRECTORY, filename)
                size = os.path.getsize(filepath)
                print(f"    [{idx}] {filename} ({size} octets)")

            while True:
                choix = input(f"\n[?] Sélectionnez un fichier (1-{len(key_files)}) : ").strip()
                try:
                    idx = int(choix)
                    if 1 <= idx <= len(key_files):
                        local_file = os.path.join(KEYS_DIRECTORY, key_files[idx - 1])
                        break
                except ValueError:
                    pass
                print(f"[✗] Veuillez choisir un nombre entre 1 et {len(key_files)}")
        else:
            afficher_erreur(f"Répertoire {KEYS_DIRECTORY} introuvable")
            return

    except PermissionError:
        afficher_erreur(f"Permission refusée pour lire {KEYS_DIRECTORY}")
        return

    # Paramètres de connexion SFTP
    print("\n[*] Configuration de la connexion SFTP :")

    config = {}
    config['host'] = input("    Hôte (IP ou domaine) : ").strip()

    port_input = input("    Port [22] : ").strip()
    config['port'] = int(port_input) if port_input else 22

    config['username'] = input("    Nom d'utilisateur : ").strip()

    print("\n[*] Mode d'authentification :")
    print("    [1] Mot de passe")
    print("    [2] Clé SSH")

    while True:
        auth_choice = input("\n[?] Choix (1-2) : ").strip()
        if auth_choice in ['1', '2']:
            break
        print("[✗] Veuillez choisir 1 ou 2")

    if auth_choice == '1':
        import getpass
        config['password'] = getpass.getpass("    Mot de passe : ")
    else:
        config['key_filename'] = input("    Chemin de la clé SSH : ").strip()

    # Chemin de destination
    remote_file = input("\n[?] Chemin de destination sur le serveur : ").strip()

    # Transfert
    print(f"\n[*] Début du transfert...")
    if send_sftp(local_file, remote_file, config):
        afficher_succes(f"Clé transférée vers {config['host']}:{remote_file}")
    else:
        afficher_erreur("Échec du transfert SFTP")


def encrypt_file(filepath, key, inplace=True):
    """
    Chiffre un fichier avec la clé fournie

    Args:
        filepath (str): Chemin du fichier à chiffrer
        key (bytes): Clé de chiffrement
        inplace (bool): Si True, remplace le fichier original

    Returns:
        bool: True si chiffrement réussi, False sinon
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        import secrets

        # Lecture du fichier original
        with open(filepath, 'rb') as f:
            plaintext = f.read()

        # Génération d'un IV (vecteur d'initialisation) aléatoire
        iv = secrets.token_bytes(16)

        # Création du cipher AES en mode CBC
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # Padding du texte (AES nécessite des blocs de 16 octets)
        padding_length = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + bytes([padding_length] * padding_length)

        # Chiffrement
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Préparation des données finales (IV + ciphertext)
        encrypted_data = iv + ciphertext

        # Écriture du fichier chiffré
        if inplace:
            output_path = filepath
        else:
            output_path = filepath + ".enc"

        with open(output_path, 'wb') as f:
            f.write(encrypted_data)

        return True

    except Exception as e:
        print(f"[✗] Erreur lors du chiffrement de {filepath} : {str(e)}")
        return False


def select_directories():
    """
    Interface interactive pour sélectionner des fichiers/dossiers

    Returns:
        list: Liste des chemins sélectionnés ou None si annulé
    """
    print("\n[*] Modes de sélection :")
    print("    [1] Fichier unique")
    print("    [2] Dossier complet")
    print("    [3] Chemin personnalisé")

    while True:
        choix = input("\n[?] Votre choix (1-3) : ").strip()
        if choix in ['1', '2', '3']:
            break
        print("[✗] Veuillez choisir 1, 2 ou 3")

    if choix == '1':
        # Fichier unique
        filepath = input("\n[?] Chemin du fichier : ").strip()
        if not os.path.exists(filepath):
            print(f"[✗] Fichier introuvable : {filepath}")
            return None
        if not os.path.isfile(filepath):
            print(f"[✗] Le chemin n'est pas un fichier : {filepath}")
            return None
        return [filepath]

    elif choix == '2':
        # Dossier complet
        dirpath = input("\n[?] Chemin du dossier : ").strip()
        if not os.path.exists(dirpath):
            print(f"[✗] Dossier introuvable : {dirpath}")
            return None
        if not os.path.isdir(dirpath):
            print(f"[✗] Le chemin n'est pas un dossier : {dirpath}")
            return None
        return [dirpath]

    else:
        # Chemin personnalisé
        path = input("\n[?] Chemin (fichier ou dossier) : ").strip()
        if not os.path.exists(path):
            print(f"[✗] Chemin introuvable : {path}")
            return None
        return [path]


def chiffrer_fichiers():
    """
    Interface utilisateur pour le chiffrement de fichiers/dossiers
    Parties E et F du TD
    """
    print("\n" + "-" * 50)
    print("CHIFFREMENT DE FICHIERS/DOSSIERS")
    print("-" * 50 + "\n")

    # Sélection de la clé
    print("[*] Sélection de la clé de chiffrement :")

    try:
        if not os.path.exists(KEYS_DIRECTORY):
            afficher_erreur(f"Répertoire {KEYS_DIRECTORY} introuvable")
            return

        key_files = [f for f in os.listdir(KEYS_DIRECTORY) if f.endswith('.json')]

        if not key_files:
            afficher_erreur("Aucun fichier de clé trouvé")
            print(f"[!] Générez d'abord une clé (option 1)")
            return

        for idx, filename in enumerate(key_files, 1):
            print(f"    [{idx}] {filename}")

        while True:
            choix = input(f"\n[?] Sélectionnez une clé (1-{len(key_files)}) : ").strip()
            try:
                idx = int(choix)
                if 1 <= idx <= len(key_files):
                    key_file = os.path.join(KEYS_DIRECTORY, key_files[idx - 1])
                    break
            except ValueError:
                pass
            print(f"[✗] Veuillez choisir un nombre entre 1 et {len(key_files)}")

        # Chargement de la clé
        import base64
        with open(key_file, 'r') as f:
            key_data = json.load(f)
            key = base64.b64decode(key_data['key'])

        print(f"[✓] Clé chargée : {key_files[idx - 1]}")

    except Exception as e:
        afficher_erreur(f"Erreur lors du chargement de la clé : {str(e)}")
        return

    # Sélection des fichiers/dossiers
    paths = select_directories()

    if paths is None:
        afficher_erreur("Sélection annulée")
        return

    # Confirmation du mode in-place
    print("\n[?] Chiffrement in-place (remplacement des fichiers originaux) ?")
    while True:
        inplace_choice = input("    Choix (O/N) : ").strip().upper()
        if inplace_choice in ['O', 'N']:
            inplace = (inplace_choice == 'O')
            break
        print("    [!] Veuillez saisir 'O' ou 'N'")

    # Collecte de tous les fichiers à chiffrer
    files_to_encrypt = []

    for path in paths:
        if os.path.isfile(path):
            files_to_encrypt.append(path)
        elif os.path.isdir(path):
            # Chiffrement récursif (Partie F)
            print(f"\n[*] Parcours récursif de {path}...")
            for root, dirs, files in os.walk(path):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    files_to_encrypt.append(filepath)

    if not files_to_encrypt:
        afficher_erreur("Aucun fichier à chiffrer")
        return

    print(f"\n[*] {len(files_to_encrypt)} fichier(s) à chiffrer")

    # Chiffrement avec barre de progression (Partie F)
    print(f"\n[*] Chiffrement en cours...")

    success_count = 0
    error_count = 0

    for idx, filepath in enumerate(files_to_encrypt, 1):
        # Barre de progression
        progress = int((idx / len(files_to_encrypt)) * 50)
        bar = "█" * progress + "░" * (50 - progress)
        percent = int((idx / len(files_to_encrypt)) * 100)

        print(f"\r[{bar}] {percent}% ({idx}/{len(files_to_encrypt)})", end='', flush=True)

        # Chiffrement du fichier
        if encrypt_file(filepath, key, inplace):
            success_count += 1
        else:
            error_count += 1

    print()  # Nouvelle ligne après la barre de progression

    # Résumé
    if error_count == 0:
        afficher_succes(f"Tous les fichiers ont été chiffrés ({success_count}/{len(files_to_encrypt)})")
    else:
        print(f"\n[!] Chiffrement terminé avec des erreurs :")
        print(f"    [✓] Réussis : {success_count}")
        print(f"    [✗] Échecs : {error_count}")


def clear_screen():
    """
    Efface l'écran du terminal (compatible Windows/Linux)
    """
    os.system('cls' if os.name == 'nt' else 'clear')


def afficher_menu():
    """
    Affiche le menu principal avec toutes les options
    """
    print("\n" + "=" * 50)
    print(" " * 10 + "SYSTÈME DE CHIFFREMENT - TD3")
    print("=" * 50)
    print("\n[1] Générer une nouvelle clé")
    print("[2] Envoyer une clé via SFTP")
    print("[3] Chiffrer des fichiers/dossiers")
    print("[4] Vérifier les dépendances")
    print("[5] Quitter")
    print("\n" + "=" * 50)


def saisir_choix_menu():
    """
    Gère la saisie utilisateur pour le menu principal avec validation

    Returns:
        int: Le choix validé de l'utilisateur (1-5)
    """
    while True:
        try:
            choix = input("\n[?] Votre choix : ").strip()

            if not choix:
                print("[✗] Erreur : Veuillez entrer un choix")
                continue

            choix_int = int(choix)

            if 1 <= choix_int <= 5:
                return choix_int
            else:
                print("[✗] Erreur : Veuillez choisir un nombre entre 1 et 5")

        except ValueError:
            print("[✗] Erreur : Veuillez entrer un nombre valide")
        except KeyboardInterrupt:
            print("\n\n[!] Interruption détectée")
            return 5


def pause():
    """
    Met en pause l'exécution et attend une action utilisateur
    """
    print()
    input("[*] Appuyez sur Entrée pour revenir au menu principal...")


def afficher_succes(message):
    """
    Affiche un message de succès formaté

    Args:
        message (str): Message à afficher
    """
    print(f"\n[✓] SUCCÈS : {message}")


def afficher_erreur(message):
    """
    Affiche un message d'erreur formaté

    Args:
        message (str): Message d'erreur à afficher
    """
    print(f"\n[✗] ERREUR : {message}")


# ========================================
# FONCTION PRINCIPALE
# ========================================

def main():
    """
    Fonction principale - Point d'entrée du programme
    Gère la boucle du menu principal
    """
    # Vérification initiale des dépendances au démarrage
    if not check_dependencies():
        print("[!] Impossible de continuer sans les dépendances requises")
        sys.exit(1)

    # Boucle principale du menu
    while True:
        try:
            afficher_menu()
            choix = saisir_choix_menu()

            if choix == 1:
                generer_cle()
                pause()

            elif choix == 2:
                envoyer_cle_sftp()
                pause()

            elif choix == 3:
                chiffrer_fichiers()
                pause()

            elif choix == 4:
                check_dependencies()
                pause()

            elif choix == 5:
                print("\n" + "=" * 50)
                print("[*] Fermeture du programme...")
                print("=" * 50 + "\n")
                sys.exit(0)

        except KeyboardInterrupt:
            print("\n\n" + "=" * 50)
            print("[!] Interruption clavier détectée (Ctrl+C)")
            print("[*] Fermeture du programme...")
            print("=" * 50 + "\n")
            sys.exit(0)

        except Exception as e:
            afficher_erreur(f"Une erreur inattendue s'est produite : {str(e)}")
            pause()


# ========================================
# POINT D'ENTRÉE
# ========================================

if __name__ == "__main__":
    main()
