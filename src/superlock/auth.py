from pathlib import Path
import json
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os, json
import secrets
from getpass import getpass
from argon2.exceptions import VerificationError, VerifyMismatchError, InvalidHashError
import hmac, hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hashlib


content = {}

ph = PasswordHasher()

def derive_master_key(master_pw: str, salt = None) -> tuple[bytes, str]:
    if not salt:
        salt = os.urandom(16)

    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=1,
        lanes=4,
        memory_cost=64 * 1024,
    )
    master_key = kdf.derive(master_pw.encode())

    return master_key, base64.b64encode(salt).decode()

def compute_auth_integrity_hmac(master_key: bytes, label: bytes, data_bytes: bytes) -> bytes:
    
    key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=label,
        ).derive(master_key)

    tag = hmac.new(key, data_bytes, hashlib.sha256).digest()

    return tag
def serialize_auth_data(data: dict) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
def authenticate():
    from .crypto import get_auth, get_mk_salt

    master_pw = getpass()

    master_key, salt= derive_master_key(master_pw, get_mk_salt())

    with open(Path.home() / ".superlock" / "auth.json", "rb") as f:
        content = json.loads(f.read())
    
    try:
        stored_tag = base64.b64decode(content.pop("hmac_tag"))
    except (KeyError, ValueError):
        raise SystemExit("Wrong password or tampered auth.json")

    data = serialize_auth_data(content)
    tag = compute_auth_integrity_hmac(master_key, b"auth.json mac", data)

    if not hmac.compare_digest(tag, stored_tag):
        raise SystemExit("Wrong password or tampered auth.json")

    hashed_pw = get_auth("password_hash")

    try:
        if ph.verify(hashed_pw, master_pw):
            return master_pw

    except InvalidHashError:
        print("Invalid Hash, corrupted auth.json")
        raise SystemExit(1) from None
    except VerifyMismatchError:
        print("Wrong password")
        raise SystemExit(1) from None
    except VerificationError:
        print("Wrong password")
        raise SystemExit(1) from None
