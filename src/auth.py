from pathlib import Path
import json
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
frop
import base64
import os
json_content = json.JSONEncoder

content = {"password_hash": None, "kdf_salt": None}

json_content.encode(content)

ph = PasswordHasher()

def set_pw(master_pw: str, auth_file: Path) -> bool:
    content["password_hash"] = ph.hash(master_pw)
    content["kdf_salt"] = derive_master_key()

    with open(auth_file, "w") as file:


        file.write()
    return True

def derive_master_key() -> str:
    salt = os.urandom(16)

    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=1,
        lanes=4,
        memory_cost=64 * 1024,


    )


    return salt


# ph.verify(hash, "password")