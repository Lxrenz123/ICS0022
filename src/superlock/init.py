#import argon2-cffi
from getpass import getpass
import os
from pathlib import Path
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from argon2 import PasswordHasher
from .crypto import get_user_key, get_auth
from .auth import derive_master_key
import base64
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .purge import purge
from .auth import compute_auth_integrity_hmac, serialize_auth_data
import sys
import json
content = dict()
ph = PasswordHasher()



def init():
    print(r"""
   _____ _    _ _____  ______ _____  _      ____   _____ _  __
  / ____| |  | |  __ \|  ____|  __ \| |    / __ \ / ____| |/ /
 | (___ | |  | | |__) | |__  | |__) | |   | |  | | |    | ' / 
  \___ \| |  | |  ___/|  __| |  _  /| |   | |  | | |    |  <
  ____) | |__| | |    | |____| | \ \| |___| |__| | |____| . \
 |_____/ \____/|_|    |______|_|  \_\______\____/ \_____|_|\_\

                  >>> Initializing Secure File Manager <<<
""")
    try:
        if (Path.home() / ".superlock").is_dir():
            reset = input('SuperLock directory already exists in your home, do you want to reset? y/n: ')
            if reset == "y":
                purge()
            else:
                return
        
        print("Press CTRL + C anytime to reset initialization and abort")
        master_pw = set_masterpw()
        root = create_superlock_root()
        setup_authjson(master_pw, root)
    

    except KeyboardInterrupt:
        print("\n")
        print("=" * 55)
        print("  [!] SUPERLOCK INITIALIZATION ABORTED")
        print("=" * 55)
        print("  Setup interrupted by user (CTRL+C).")
        print("  No further initialization will be performed.")
        print("=" * 55)
        print()
    


def create_superlock_root():
    try:
        superlock_dir = Path.home() / ".superlock"
        Path.mkdir(superlock_dir, exist_ok=True)

        Path.mkdir(superlock_dir / "vault", exist_ok=True)

        print(f"[+] {superlock_dir} successfully created")
    except FileExistsError:
        print(f"{superlock_dir} already exists, abort")
        sys.exit(1)
    return superlock_dir

def set_masterpw():
    master_pw = ""
    master_pw_confirm = ""
    while master_pw != master_pw_confirm or len(master_pw) == 0 or len(master_pw_confirm) == 0 or not len(master_pw) >= 8:
        print("-- Please setup your master password --")
        master_pw = getpass(prompt="Master Password: ")
        master_pw_confirm = getpass(prompt="Confirm Master: ")
        if master_pw != master_pw_confirm:
            print("Passwords are different, please try again!")
        elif len(master_pw) < 8:
            print("Minimum password length is 8, please try again")
    print("[+] Master password set up successful")
    return master_pw




def setup_authjson(master_pw: str, root: Path) -> bool:
    content["password_hash"] = ph.hash(master_pw)
    master_key, salt_master_key = derive_master_key(master_pw)
    content["kdf_salt"] = salt_master_key


    user_key_wrapped, salt_user_key = gen_user_key_wrapped(master_key)
    content["wrapped_user_key"] = user_key_wrapped
    content["user_key_nonce"] =  salt_user_key
    data = serialize_auth_data(content)
    content["hmac_tag"] = base64.b64encode(
        compute_auth_integrity_hmac(master_key, b"auth.json mac", data)
    ).decode()
    fd = os.open(root / "auth.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,)

    with os.fdopen(fd, "wb") as f:
        f.write(serialize_auth_data(content))
        f.flush()
        os.fsync(f.fileno())

    create_index(master_pw, root)

    return True



def gen_user_key_wrapped(master_key: bytes):

    user_key = secrets.token_bytes(32)

    nonce = os.urandom(12)

    user_key_enc = AESGCM(master_key).encrypt(nonce, user_key, None)

    return base64.b64encode(user_key_enc).decode(), base64.b64encode(nonce).decode()


def create_index(master_pw: str, root: Path):
    try:
        flags = (os.O_RDONLY
         | getattr(os, "O_NOFOLLOW", 0)
         | getattr(os, "O_NONBLOCK", 0)
         | getattr(os, "O_CLOEXEC", 0)
         | getattr(os, "O_BINARY", 0))
        fd = os.open(root / "auth.json", flags)

        with os.fdopen(fd, "r") as file:
            auth = file.read()
            auth = json.loads(auth)


        key, salt = derive_master_key(master_pw, get_auth("kdf_salt"))
        user_key = get_user_key(key)
        nonce = os.urandom(12)

        index = json.dumps({}).encode()

        fd = os.open(root / "index.enc", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,)

        with os.fdopen(fd, "wb") as file:
            enc = AESGCM(user_key).encrypt(nonce,index, None)
            file.write(nonce + enc)
    except Exception:
        print("Error")
        sys.exit(1)
