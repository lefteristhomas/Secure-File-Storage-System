#2η Εργασία — Ασφάλεια Συστημάτων
#Secure File Storage System

import os
import json
import secrets
import base64
import hashlib
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# ──────────────────────────────────────────────────────
# ΣΤΑΘΕΡΕΣ
# ──────────────────────────────────────────────────────
#ΑΑΑΑ
USERS_DB    = Path('users.json')
STORAGE_DIR = Path('secure_storage')
KEYS_DIR    = Path('keys')
NONCE_DB    = Path('nonces.json')
OTP_DB      = Path('otp_store.json')


# ──────────────────────────────────────────────────────
# ΑΡΧΙΚΟΠΟΙΗΣΗ ΣΥΣΤΗΜΑΤΟΣ (Δίνεται)
# ──────────────────────────────────────────────────────
def initialize_system():
    STORAGE_DIR.mkdir(exist_ok=True)
    KEYS_DIR.mkdir(exist_ok=True)
    for f, default in [(USERS_DB, {}), (NONCE_DB, []), (OTP_DB, {})]:
        if not f.exists():
            f.write_text(json.dumps(default))
#ΕΕΕΕΕΕΕ

# ──────────────────────────────────────────────────────
# ΜΕΡΟΣ Α — Hash & Salt (από Εργασία 1)
# ──────────────────────────────────────────────────────
def hash_password(password: str, salt: str = None) -> tuple:
    """Επιστρέφει (hash_hex, salt_hex) χρησιμοποιώντας PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = secrets.token_hex(16)
    salt_bytes = bytes.fromhex(salt)
    hash_bytes = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt_bytes,
        100000,
        dklen=32
    )
    return hash_bytes.hex(), salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Επιστρέφει True αν ο κωδικός είναι σωστός."""
    computed_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(computed_hash, stored_hash)


# ──────────────────────────────────────────────────────
# ΜΕΡΟΣ Β — OTP & Εγγραφή Χρήστη
# ──────────────────────────────────────────────────────
#ΑΑΑΑΑ
def admin_issue_otp(username: str) -> str:
    """Διαχειριστής: δημιουργεί και αποθηκεύει OTP για username."""
    otp = secrets.token_hex(4).upper()   # 8-ψήφιο hex OTP
    store = json.loads(OTP_DB.read_text())
    store[username] = {
        "otp": otp,
        "issued_at": datetime.now().isoformat(),
        "used": False
    }
    OTP_DB.write_text(json.dumps(store, indent=2))
    print(f"[ADMIN] OTP για '{username}': {otp}")
    return otp

#ΕΕΕΕΕΕΕ
def register_user(username: str, otp_input: str, password: str) -> bool:
    """Εγγραφή χρήστη με επαλήθευση OTP."""
    # 1. Φόρτωση OTP_DB
    try:
        otp_store = json.loads(OTP_DB.read_text())
    except Exception:
        otp_store = {}

    # 2. Έλεγχος αν υπάρχει OTP για το username
    if username not in otp_store:
        print("Δεν βρέθηκε OTP για αυτό το username. Επικοινωνήστε με τον διαχειριστή.")
        return False

    otp_data = otp_store[username]

    # 3. Έλεγχος αν το OTP έχει ήδη χρησιμοποιηθεί
    if otp_data.get("used", False):
        print("Αυτό το OTP έχει ήδη χρησιμοποιηθεί!")
        return False

    # 4. Σύγκριση OTP (case-insensitive)
    if otp_input.upper() != otp_data["otp"]:
        print("Λάθος OTP!")
        return False

    # 5. Σήμανση OTP ως χρησιμοποιημένο
    otp_data["used"] = True
    otp_store[username] = otp_data
    OTP_DB.write_text(json.dumps(otp_store, indent=2))

    # 6. Έλεγχος αν ο χρήστης υπάρχει ήδη
    try:
        users = json.loads(USERS_DB.read_text())
    except Exception:
        users = {}

    if username in users:
        print("Ο χρήστης υπάρχει ήδη!")
        return False

    # 7. Hash + salt του password
    hash_value, salt = hash_password(password)
    users[username] = {
        "password_hash": hash_value,
        "salt": salt,
        "created_at": datetime.now().isoformat()
    }
    USERS_DB.write_text(json.dumps(users, indent=2))

    # 8. Δημιουργία κλειδιών RSA
    generate_user_keys(username)

    # 9. Επιβεβαίωση
    print(f"Ο χρήστης '{username}' εγγράφηκε επιτυχώς!")
    return True


# ──────────────────────────────────────────────────────
# ΜΕΡΟΣ Γ — Αυθεντικοποίηση
# ──────────────────────────────────────────────────────
def authenticate_user(username: str, password: str) -> bool:
    """Έλεγχος στοιχείων σύνδεσης."""
    try:
        users = json.loads(USERS_DB.read_text())
    except Exception:
        users = {}

    # Πάντα το ίδιο μήνυμα — δεν αποκαλύπτουμε αν υπάρχει ο χρήστης
    if username not in users:
        return False

    user_data = users[username]
    stored_hash = user_data["password_hash"]
    salt = user_data["salt"]

    return verify_password(password, stored_hash, salt)



#ΑΑΑΑΑΑ
# ──────────────────────────────────────────────────────
# ΜΕΡΟΣ Δ — Κλειδιά RSA (Δίνεται)
# ──────────────────────────────────────────────────────
def generate_user_keys(username: str):
    """Δημιουργία RSA-2048 ζεύγους κλειδιών."""
    pk = rsa.generate_private_key(65537, 2048, default_backend())
    (KEYS_DIR / f"{username}_private.pem").write_bytes(
        pk.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.TraditionalOpenSSL,
                         serialization.NoEncryption()))
    (KEYS_DIR / f"{username}_public.pem").write_bytes(
        pk.public_key().public_bytes(serialization.Encoding.PEM,
                                     serialization.PublicFormat.SubjectPublicKeyInfo))


def load_private_key(username: str):
    return serialization.load_pem_private_key(
        (KEYS_DIR / f"{username}_private.pem").read_bytes(),
        password=None, backend=default_backend())


def load_public_key(username: str):
    return serialization.load_pem_public_key(
        (KEYS_DIR / f"{username}_public.pem").read_bytes(),
        backend=default_backend())


# ──────────────────────────────────────────────────────
# ΜΕΡΟΣ Ε — Nonce / Anti-Replay
# ──────────────────────────────────────────────────────
def generate_nonce() -> str:
    return secrets.token_hex(16)

#ΕΕΕΕΕΕΕ
def is_nonce_valid(nonce: str) -> bool:
    """Έλεγχος αν το nonce είναι μοναδικό (anti-replay)."""
    try:
        nonces = json.loads(NONCE_DB.read_text())
    except Exception:
        nonces = []

    if nonce in nonces:
        print(f"ΠΡΟΕΙΔΟΠΟΙΗΣΗ: Ανιχνεύθηκε Replay Attack! Το nonce '{nonce}' έχει χρησιμοποιηθεί ξανά.")
        return False

    nonces.append(nonce)
    NONCE_DB.write_text(json.dumps(nonces, indent=2))
    return True


# ──────────────────────────────────────────────────────
# ΜΕΡΟΣ ΣΤα — Κρυπτογράφηση AES-256-GCM
# ──────────────────────────────────────────────────────
def encrypt_file(data: bytes) -> tuple:
    """Κρυπτογράφηση με AES-256-GCM. Επιστρέφει (ciphertext, key, nonce_aes)."""
    key = os.urandom(32)
    nonce_aes = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce_aes, data, None)
    return ciphertext, key, nonce_aes


def decrypt_file(ciphertext: bytes, key: bytes, nonce_aes: bytes) -> bytes:
    """Αποκρυπτογράφηση AES-256-GCM."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce_aes, ciphertext, None)


# ──────────────────────────────────────────────────────
# ΜΕΡΟΣ ΣΤβ — Ψηφιακή Υπογραφή RSA-PSS
# ──────────────────────────────────────────────────────
def sign_data(username: str, data: bytes, nonce: str) -> bytes:
    """Ψηφιακή υπογραφή RSA-PSS+SHA256."""
    private_key = load_private_key(username)
    payload = data + nonce.encode('utf-8')
    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(username: str, data: bytes, nonce: str, sig: bytes) -> bool:
    """Επαλήθευση ψηφιακής υπογραφής. Επιστρέφει True/False."""
    try:
        public_key = load_public_key(username)
        payload = data + nonce.encode('utf-8')
        public_key.verify(
            sig,
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ──────────────────────────────────────────────────────
# ΜΕΡΟΣ Ζα — Upload Αρχείου
# ──────────────────────────────────────────────────────
def upload_file(username: str, filepath: str):
    """Ανέβασμα αρχείου με ασφάλεια: sign → nonce-check → encrypt → save."""
    # 1. Ανάγνωση αρχείου
    try:
        data = Path(filepath).read_bytes()
    except FileNotFoundError:
        print(f"Το αρχείο '{filepath}' δεν βρέθηκε!")
        return

    # 2. Παραγωγή nonce
    nonce = generate_nonce()

    # 3. Ψηφιακή υπογραφή
    try:
        signature = sign_data(username, data, nonce)
    except Exception as e:
        print(f"Σφάλμα κατά την υπογραφή: {e}")
        return

    # 4. Έλεγχος nonce (anti-replay)
    if not is_nonce_valid(nonce):
        print("Το nonce δεν είναι έγκυρο! Πιθανή Replay Attack.")
        return

    # 5. Κρυπτογράφηση
    ciphertext, key, nonce_aes = encrypt_file(data)

    # 6. Αποθήκευση κρυπτογραφημένου αρχείου
    original_filename = Path(filepath).name
    enc_filepath = STORAGE_DIR / (original_filename + ".enc")
    enc_filepath.write_bytes(ciphertext)

    # 7. Αποθήκευση metadata
    metadata = {
        "original_filename": original_filename,
        "uploader": username,
        "nonce": nonce,
        "nonce_aes": base64.b64encode(nonce_aes).decode('utf-8'),
        "key": base64.b64encode(key).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8'),
        "timestamp": datetime.now().isoformat()
    }
    metadata_filepath = STORAGE_DIR / (original_filename + ".json")
    metadata_filepath.write_text(json.dumps(metadata, indent=2))

    print(f"Το αρχείο '{original_filename}' ανέβηκε επιτυχώς!")
    print(f"   Κρυπτογραφημένο: {enc_filepath}")
    print(f"   Metadata:        {metadata_filepath}")


# ──────────────────────────────────────────────────────
# ΜΕΡΟΣ Ζβ — Download Αρχείου
# ──────────────────────────────────────────────────────
def download_file(username: str, filename: str):
    """Λήψη, αποκρυπτογράφηση και επαλήθευση αρχείου."""
    enc_filepath      = STORAGE_DIR / (filename + ".enc")
    metadata_filepath = STORAGE_DIR / (filename + ".json")

    # 1. Φόρτωση metadata
    if not metadata_filepath.exists():
        print(f"Τα metadata για '{filename}' δεν βρέθηκαν!")
        return

    try:
        metadata = json.loads(metadata_filepath.read_text())
    except Exception as e:
        print(f"Σφάλμα ανάγνωσης metadata: {e}")
        return

    # 2. Έλεγχος δικαιωμάτων
    if metadata["uploader"] != username:
        print("Δεν έχετε δικαίωμα να κατεβάσετε αυτό το αρχείο!")
        return

    # 3. Ανάγνωση κρυπτογραφημένου αρχείου
    if not enc_filepath.exists():
        print(f"Το αρχείο '{filename}.enc' δεν βρέθηκε!")
        return

    ciphertext = enc_filepath.read_bytes()

    # 4. Αποκωδικοποίηση base64
    try:
        key       = base64.b64decode(metadata["key"])
        nonce_aes = base64.b64decode(metadata["nonce_aes"])
        signature = base64.b64decode(metadata["signature"])
        nonce     = metadata["nonce"]
    except Exception as e:
        print(f"Σφάλμα αποκωδικοποίησης metadata: {e}")
        return

    # 5. Αποκρυπτογράφηση
    try:
        plaintext = decrypt_file(ciphertext, key, nonce_aes)
    except Exception as e:
        print(f"Σφάλμα αποκρυπτογράφησης: {e}")
        return

    # 6. Επαλήθευση υπογραφής
    if not verify_signature(username, plaintext, nonce, signature):
        print("ΠΡΟΕΙΔΟΠΟΙΗΣΗ: Η ψηφιακή υπογραφή ΔΕΝ επαληθεύτηκε! Το αρχείο μπορεί να έχει παραβιαστεί.")
        return

    # 7. Αποθήκευση αρχείου
    original_filename  = metadata["original_filename"]
    downloaded_filepath = Path(f"downloaded_{original_filename}")
    downloaded_filepath.write_bytes(plaintext)

    print(f"Το αρχείο '{original_filename}' κατέβηκε επιτυχώς!")
    print(f"Αποθηκεύτηκε ως: {downloaded_filepath}")
    print("Η ψηφιακή υπογραφή επαληθεύτηκε. ✓")


# ──────────────────────────────────────────────────────
# ΜΕΝΟΥ (Δίνεται — μην αλλάζεις)
# ──────────────────────────────────────────────────────
def show_menu():
    print("\n" + "="*48)
    print("  Secure File Storage — Εργασία 2")
    print("="*48)
    print("  1. Εγγραφή (με OTP)")
    print("  2. Σύνδεση")
    print("  3. Ανέβασμα αρχείου")
    print("  4. Κατέβασμα αρχείου")
    print("  9. [Admin] Έκδοση OTP")
    print("  0. Έξοδος")
    print("="*48)

# ──────────────────────────────────────────────────────
# ΜΕΡΟΣ Ζγ — Κύριο CLI Loop
# ──────────────────────────────────────────────────────
def main():
    initialize_system()
    logged_in_user = None

    while True:
        show_menu()
        choice = input("Επιλογή: ").strip()

        if choice == "1":
            # Εγγραφή
            username = input("Username: ").strip()
            otp      = input("OTP: ").strip()
            password = input("Password: ").strip()
            register_user(username, otp, password)

        elif choice == "2":
            # Σύνδεση
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            if authenticate_user(username, password):
                logged_in_user = username
                print(f"Καλώς ήρθες, {username}!")
            else:
                print("Λάθος στοιχεία σύνδεσης.")

        elif choice == "3":
            # Upload
            if logged_in_user is None:
                print("Πρέπει πρώτα να συνδεθείτε!")
            else:
                filepath = input("Διαδρομή αρχείου: ").strip()
                upload_file(logged_in_user, filepath)

        elif choice == "4":
            # Download
            if logged_in_user is None:
                print("Πρέπει πρώτα να συνδεθείτε!")
            else:
                filename = input("Όνομα αρχείου (χωρίς .enc): ").strip()
                download_file(logged_in_user, filename)

        elif choice == "9":
            # Admin: Έκδοση OTP
            username = input("Username για OTP: ").strip()
            admin_issue_otp(username)

        elif choice == "0":
            print("Αποχώρηση...")
            break

        else:
            print("Μη έγκυρη επιλογή!")

if __name__ == "__main__":
    main()