from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import exceptions
import uuid
import json
import os
import stat
import time
from .auth import derive_master_key
from pathlib import Path
import base64
from .auth import authenticate
from .log import logger
import sys

root = Path.home() /".superlock"

MAGIC = bytes.fromhex("534C5631")
LENGTH_SIZE = 4
INDEX_NONCE_SIZE = 12

INDEX = root / "index.enc"

def encrypt(path: str, name: str = None):


    master_key, _ = derive_master_key(authenticate(), get_auth("kdf_salt"))

    kek = get_kek(master_key)

    p = Path(path).expanduser()
    if not name:
        name = p.name

    index = decrypt_index(master_key)
    if name in index.values():
        logger.error("A file with this name already exists in your vault, please choose a different name!")
        sys.exit(1)


    aad_header, key, file_nonce, file_id = generate_header(kek)

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(p, flags, 0o600)
        os.fchmod(fd, 0o600)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise OSError("input is not a regular file")
    except OSError:
        logger.error("Encryption failed: Invalid path")
        sys.exit(1)


    with os.fdopen(fd, "rb") as file:
        data = file.read()


    ct = AESGCM(key).encrypt(file_nonce, data, aad_header)

    encrypted_path = root / "vault" / f"{file_id}.sl"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL

    try:
        fd = os.open(encrypted_path, flags, 0o600)
        os.fchmod(fd, 0o600)
    except OSError:
        logger.error("Encryption failed: unable to create vault file")
        sys.exit(1)

    with os.fdopen(fd, "wb") as file:
        file.write(aad_header)
        file.write(ct)


    if not add_to_index({file_id: name}, master_key):
        logger.error("Encryption failed: failed to add file to Index")
        sys.exit(1)
    logger.info("Encryption succeeded")

def get_kek(master_key: bytes):

    get_auth("wrapped_kek")

    kek_enc = get_auth("wrapped_kek")
    kek_salt = get_auth("kek_salt")

    kek = AESGCM(master_key).decrypt(kek_salt, kek_enc, None)

    return kek



def generate_header(kek):
    header = []
    header.append(MAGIC)

    key = AESGCM.generate_key(bit_length=256)
    wrap_nonce = os.urandom(12)
    file_nonce = os.urandom(12)

    file_id = str(uuid.uuid4())
    owner = os.getuid()
    created = time.time()
    algo = "AES-GCM-256"
    wrapped_key = AESGCM(kek).encrypt(nonce=wrap_nonce, data=key, associated_data=None)

   
    header_dict = {
        "file_id": file_id,
        "owner": owner,
        "created": created,
        "algo": algo,
        "wrap_nonce": base64.b64encode(wrap_nonce).decode(),
        "file_nonce": base64.b64encode(file_nonce).decode(),
        "wrapped_key": base64.b64encode(wrapped_key).decode(),
    }
    header_json = json.dumps(header_dict).encode()

    header.append(len(header_json).to_bytes(4))
    header.append(header_json)

    return b"".join(header), key, file_nonce, file_id


def decrypt(filename: str, stdout: bool = False, output_path: str | os.PathLike | None = None):

    master_key, _ = derive_master_key(authenticate(), get_auth("kdf_salt"))
    kek = get_kek(master_key=master_key)
    filepath = lookup_index(filename, master_key)

    full_file_path = Path(root / "vault" / filepath)

    vault_path = root / "vault" / filepath
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(vault_path, flags)
    except OSError:
        logger.error("Decryption failed: Invalid vault file")
        sys.exit(1)

    with os.fdopen(fd, "rb") as file:
        try:
            data = file.read()

            magic_end = len(MAGIC)
            length_end = magic_end + LENGTH_SIZE

            header_length = int.from_bytes(
                data[magic_end:length_end]
            )

            header_end = length_end + header_length


            header = data[:header_end]
            header_json = json.loads(data[length_end:header_end].decode("utf-8"))

            wrap_nonce = base64.b64decode(header_json["wrap_nonce"])
            file_nonce = base64.b64decode(header_json["file_nonce"])
            wrapped_key = base64.b64decode(header_json["wrapped_key"])

            ciphertext = data[header_end:]

            file_key = AESGCM(kek).decrypt(
                wrap_nonce,
                wrapped_key,
                None,
            )
        except (KeyError, ValueError):
            logger.critical(
                f"Decryption failed: Integrity verification failed! "
                f"{full_file_path} was most likely tampered"
            )
            sys.exit(1)
        try:
            plain_bytes = AESGCM(file_key).decrypt(
                file_nonce,
                ciphertext,
                header,
            )
        except exceptions.InvalidTag:
            logger.critical(
                f"Decryption failed: Integrity verification failed! "
                f"{full_file_path} was most likely tampered"
            )
            sys.exit(1)
        except Exception:
            logger.error("Decryption failed")
            sys.exit(1)

        if stdout:
            if hasattr(sys.stdout, "buffer"):
                sys.stdout.buffer.write(plain_bytes)
            else:
                sys.stdout.write(plain_bytes.decode("utf-8", errors="surrogateescape"))
            sys.stdout.flush()
        else:
            destination = (
                Path(output_path).expanduser()
                if output_path is not None
                else Path.cwd() / Path(filename).name
            )
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_TRUNC
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_BINARY", 0)
            )
            try:
                fd = os.open(destination, flags, 0o600)
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as recovered:
                    recovered.write(plain_bytes)
            except OSError:
                logger.error("Decryption failed: unable to write recovered file")
                sys.exit(1)

        logger.info("Decryption succeeded")
        return plain_bytes
        

def lookup_index(filename: str, master_key: bytes | None = None):

    index = decrypt_index(master_key)
    for uuid, filen in index.items():
        if filen == filename:
            return uuid + ".sl"

    logger.error("File not found!")
    sys.exit(1)

def decrypt_index(master_key= None):

    if not master_key:
        master_key, _ = derive_master_key(authenticate(), get_auth("kdf_salt"))

    kek = get_kek(master_key)
    try:

        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(INDEX, flags)
        with os.fdopen(fd, "rb") as file:
            index_enc = file.read()
            nonce = index_enc[:INDEX_NONCE_SIZE]
            ciphertext = index_enc[INDEX_NONCE_SIZE:]
            index_plain = AESGCM(kek).decrypt(nonce, ciphertext, None).decode()
    except OSError:
        logger.error("Decryption failed: Invalid index file")
        sys.exit(1)
    except exceptions.InvalidTag:
        logger.critical(f"Decryption of Index {INDEX}: Integrity verification failed!")
        sys.exit(1)
        
    return json.loads(index_plain)

def ls_vault():
    index = decrypt_index()

    print("\nVault files")
    print("-" * 40)
    if not index:
        print("  (empty)")
    else:
        for number, filename in enumerate(index.values(), start=1):
            print(f"{number:>3}. {filename}")
    print(f"\nTotal: {len(index)} file(s)")



def add_to_index(entry: dict, master_key):
    index = decrypt_index(master_key)
    index.update(entry)

    kek = get_kek(master_key)
    nonce = os.urandom(INDEX_NONCE_SIZE)

    index_enc = AESGCM(kek).encrypt(
        nonce,
        json.dumps(index).encode(),
        None,
    )


    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_TRUNC
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(INDEX, flags, 0o600)
        os.fchmod(fd, 0o600)
    except OSError:
        logger.error("Encryption failed: unable to write index file")
        sys.exit(1)

    with os.fdopen(fd, "wb") as file:
        file.write(nonce + index_enc)

    return True


def remove_from_index(filename: str, master_key: bytes):
    index = decrypt_index(master_key)
    file_id = next(
        (file_id for file_id, stored_filename in index.items()
         if stored_filename == filename),
        None,
    )
    if file_id is None:
        logger.error("File not found in index")
        sys.exit(1)


    del index[file_id]
    kek = get_kek(master_key)
    nonce = os.urandom(INDEX_NONCE_SIZE)
    index_enc = AESGCM(kek).encrypt(
        nonce,
        json.dumps(index).encode(),
        None,
    )


    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_TRUNC
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(INDEX, flags, 0o600)
        os.fchmod(fd, 0o600)
    except OSError:
        logger.error("Failed to write index file")
        sys.exit(1)

    with os.fdopen(fd, "wb") as file:
        file.write(nonce + index_enc)

def get_auth(key: str):
    with open(root / "auth.json", "r") as file:
        auth = file.read()
        try:
            auth_dict = json.loads(auth)
        except json.JSONDecodeError:
            logger.critical("Failed to read auth.json: Integrity verification failed!")
            sys.exit(1)

    if key == "password_hash":
        return auth_dict.get(key)
            
    return base64.b64decode(auth_dict.get(key))
