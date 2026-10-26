from pathlib import Path
import json
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os
import secrets
from .log import logger
from getpass import getpass
from argon2.exceptions import VerificationError, VerifyMismatchError, InvalidHashError



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



def authenticate():
    from .crypto import get_auth

    master_pw = getpass()

    hashed_pw = get_auth("password_hash")

    try:
        if ph.verify(hashed_pw, master_pw):
            return master_pw

    except InvalidHashError:
        print("Invalid Hash, corrupted auth.json")
        raise SystemExit(1) from None
    except VerifyMismatchError:
        print("Authentication failed")
        raise SystemExit(1) from None
    except VerificationError:
        print("Authentication failed")
        raise SystemExit(1) from None

