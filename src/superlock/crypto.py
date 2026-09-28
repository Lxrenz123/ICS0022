from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import uuid
import json
import os
import time
from .auth import derive_master_key()
from pathlib import Path
import base64
root = Path.home() /".superlock"

def encrypt(path: str):
    key = secrets.token_bytes(32)

    master_pw = "test"

    master_key, salt = derive_master_key(master_pw, get_mk_salt())

    user_key = get_user_key(master_key)

    aad_header, key, nonce, file_id = generate_header(user_key)

    p = Path(path).expanduser()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(p, flags)
    except OSError:
        raise ValueError("invalid path")

    with os.fdopen(fd, "rb") as file:
        data = file.read()

    # aad_header to bytes

    data_enc = AESGCM(key).encrypt(nonce, data, aad_header)

    with open(root / f"vault/{file_id}.sl" ,"wb") as file:
        file.write(data_enc)


def get_mk_salt():
    with open(root / "auth.json", "r") as file:
        content = json.loads(file.read())
        salt = content["kdf_salt"]
    return base64.b64decode(salt.decode())

def get_user_key(master_key: bytes):
    with open(root / "auth.json","r") as file:
        content = json.loads(file.read())
        user_key_enc = base64.b64decode(content["wrapped_user_key"].decode())
        user_key_nonce = base64.b64decode(content["user_key_nonce"].decode())

        user_key = AESGCM(master_key).decrypt(user_key_nonce, user_key_enc, None)

    return user_key



def generate_header(user_key):
    header = list()
    header.append(bytes.fromhex("534C5631"))

    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)

    file_id = uuid.uuid4()
    owner = os.getuid()
    created = time.time()
    algo = "AES-GCM-256"
    nonce = os.urandom(12)
    wrapped_key = AESGCM(user_key).encrypt(nonce=nonce, data=key,aad=None)

    header_dict = {"file_id":file_id,"owner":owner,"created":created,"algo":algo,"nonce":nonce,"wrapped_key":wrapped_key}

    header_json = json.dumps(header_dict).encode()

    header.append(bytes(len(header_json)))
    header.append(header_json)

    return b"".join(header), key, nonce, file_id