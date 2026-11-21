from pathlib import Path
import json
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import base64
import os, json
from getpass import getpass
import hmac, hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hashlib
from .log import logger
import sys

root = Path.home() /".superlock"

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
    from .crypto import get_auth
    try:
        master_pw = getpass()
    except KeyboardInterrupt:
        print("\n")
        print("Aborted")
        sys.exit(1)
    master_key, _ = derive_master_key(master_pw, get_auth("kdf_salt"))
    with open(root / "auth.json", "rb") as f:
        content = json.loads(f.read())
    
    try:
        stored_tag = base64.b64decode(content.pop("hmac_tag"))
    except (KeyError, ValueError):
        logger.critical(f"missing hmac_tag in {root / "auth.json"}")
        sys.exit(1)

    data = serialize_auth_data(content)
    tag = compute_auth_integrity_hmac(master_key, b"auth.json mac", data)

    if not hmac.compare_digest(tag, stored_tag):
        logger.error("Authentication failed")
        sys.exit(1)

    return master_pw
