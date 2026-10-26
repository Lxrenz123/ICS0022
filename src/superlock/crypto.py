from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import uuid
import json
import os
import time
from .auth import derive_master_key
from pathlib import Path
import base64
from getpass import getpass
from .auth import authenticate


root = Path.home() /".superlock"

MAGIC = bytes.fromhex("534C5631")
LENGTH_SIZE = 4

def encrypt(path: str):
    key = secrets.token_bytes(32)
    master_key, salt = derive_master_key(authenticate(), get_mk_salt())

    user_key = get_user_key(master_key)
    aad_header, key, file_nonce, file_id = generate_header(user_key)

    p = Path(path).expanduser()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(p, flags)
    except OSError:
        raise ValueError("invalid path")

    with os.fdopen(fd, "rb") as file:
        data = file.read()


    ct = AESGCM(key).encrypt(file_nonce, data, aad_header)

    with open(root / f"vault/{file_id}.sl" ,"wb") as file:
        file.write(aad_header)
        file.write(ct)

    if not add_to_index({file_id: p.name}, master_key):
        raise Exception("Failed to add to Index")
    


def get_mk_salt():
    with open(root / "auth.json", "r") as file:
        content = json.loads(file.read())
        salt = content["kdf_salt"]
    return base64.b64decode(salt.encode())



def get_user_key(master_key: bytes):

    get_auth("wrapped_user_key")

    user_key_enc = get_auth("wrapped_user_key")
    user_key_nonce = get_auth("user_key_nonce")

    user_key = AESGCM(master_key).decrypt(user_key_nonce, user_key_enc, None)

    return user_key



def generate_header(user_key):
    header = list()
    header.append(MAGIC)

    key = AESGCM.generate_key(bit_length=256)
    wrap_nonce = os.urandom(12)
    file_nonce = os.urandom(12)

    file_id = str(uuid.uuid4())
    owner = os.getuid()
    created = time.time()
    algo = "AES-GCM-256"
    wrapped_key = AESGCM(user_key).encrypt(nonce=wrap_nonce, data=key, associated_data=None)

   
    header_dict = {
        "file_id": str(uuid.uuid4()),
        "owner": os.getuid(),
        "created": time.time(),
        "algo": "AES-GCM-256",
        "wrap_nonce": base64.b64encode(wrap_nonce).decode(),
        "file_nonce": base64.b64encode(file_nonce).decode(),
        "wrapped_key": base64.b64encode(wrapped_key).decode(),
    }
    header_json = json.dumps(header_dict).encode()

    header.append(len(header_json).to_bytes(4))
    header.append(header_json)

    return b"".join(header), key, file_nonce, file_id


def decrypt(filename: str):

    master_key, salt = derive_master_key(authenticate(), get_mk_salt())
    user_key = get_user_key(master_key=master_key)
    filepath = lookup_index(filename, master_key)


    with open(root / "vault" / filepath, "rb") as file:
        data = file.read()

        if len(data) < len(MAGIC) + LENGTH_SIZE:
            raise ValueError("Encrypted file is too short")

        if data[:len(MAGIC)] != MAGIC:
            raise ValueError("Invalid file magic")

        magic_end = len(MAGIC)
        length_end = magic_end + LENGTH_SIZE

        header_length = int.from_bytes(
            data[magic_end:length_end]
        )

        header_end = length_end + header_length

        if header_end > len(data):
            raise ValueError("Invalid header length")


        header = data[:header_end]
        header_json = json.loads(data[length_end:header_end].decode("utf-8"))

        wrap_nonce = base64.b64decode(header_json["wrap_nonce"])
        file_nonce = base64.b64decode(header_json["file_nonce"])
        wrapped_key = base64.b64decode(header_json["wrapped_key"])

        ciphertext = data[header_end:]

        file_key = AESGCM(user_key).decrypt(
            wrap_nonce,
            wrapped_key,
            None,
        )

        plain_bytes = AESGCM(file_key).decrypt(
            file_nonce,
            ciphertext,
            header,
        )
        
        print(plain_bytes)

    

def lookup_index(filename: str, master_key: bytes | None = None):

    index = decrypt_index(master_key)
    for uuid, filen in index.items():
        if filen == filename:
            return uuid + ".sl"
    
    raise Exception("File not found") 

def decrypt_index(master_key= None):

    if not master_key:
        master_key, salt = derive_master_key(authenticate(), get_mk_salt())

    user_key = get_user_key(master_key)
    with open(root / "index.enc", "rb") as file:
        index_enc = file.read()
        index_plain = AESGCM(user_key).decrypt(get_auth("nonce_index"),index_enc, None).decode()

    return json.loads(index_plain)

def ls_vault():

   index = decrypt_index()

   for value in index.values():
       print(value)



def add_to_index(entry: dict, master_key):
    index = decrypt_index(master_key)
    index.update(entry)

    user_key = get_user_key(master_key)
    nonce = get_auth("nonce_index")

    index_enc = AESGCM(user_key).encrypt(
        nonce,
        json.dumps(index).encode(),
        None,
    )

    with open(root / "index.enc", "wb") as file:
        file.write(index_enc)

    return True


def remove_from_index(filename: str, master_key: bytes):
    index = decrypt_index(master_key)
    file_id = next(
        (file_id for file_id, stored_filename in index.items()
         if stored_filename == filename),
        None,
    )
    if file_id is None:
        raise FileNotFoundError(f"File not found in index: {filename}")

    del index[file_id]
    user_key = get_user_key(master_key)
    nonce = get_auth("nonce_index")
    index_enc = AESGCM(user_key).encrypt(
        nonce,
        json.dumps(index).encode(),
        None,
    )

    with open(root / "index.enc", "wb") as file:
        file.write(index_enc)


def get_auth(key: str):
    with open(root / "auth.json", "r") as file:
        auth = file.read()
        auth_dict = json.loads(auth)

    if key == "password_hash":
        return auth_dict[key]

    return base64.b64decode(auth_dict.get(key))
