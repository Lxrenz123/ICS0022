from pathlib import Path
import json
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os
import secrets
from .log import logger


content = dict()



ph = PasswordHasher()

def setup_authjson(master_pw: str, root: Path) -> bool:
    content["password_hash"] = ph.hash(master_pw)
    master_key, salt_master_key = derive_master_key(master_pw)
    content["kdf_salt"] = salt_master_key


    user_key_wrapped, salt_user_key = gen_user_key_wrapped(master_key)
    content["wrapped_user_key"] = user_key_wrapped
    content["user_key_nonce"] =  salt_user_key

    with open(root / "auth.json", "w") as file:
        file.write(json.dumps(content))
    return True

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


# ph.verify(hash, "password")

def gen_user_key_wrapped(master_key: bytes):

    user_key = secrets.token_bytes(32)

    nonce = os.urandom(12)

    user_key_enc = AESGCM(master_key).encrypt(nonce, user_key, None)

    return base64.b64encode(user_key_enc).decode(), base64.b64encode(nonce).decode()