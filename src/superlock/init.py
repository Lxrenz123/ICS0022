#import argon2-cffi
from getpass import getpass
import os
from pathlib import Path
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from argon2 import PasswordHasher
from .crypto import get_user_key, get_mk_salt, get_auth
from .auth import derive_master_key
import base64
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .purge import purge
import hmac
from .auth import compute_auth_integrity_hmac, serialize_auth_data

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
        exit()
    return superlock_dir

def set_masterpw():
    master_pw = ""
    master_pw_confirm = ""
    while master_pw != master_pw_confirm or len(master_pw) == 0 or len(master_pw_confirm) == 0:
        master_pw = getpass(prompt="Master Password: ")
        master_pw_confirm = getpass(prompt="Confirm Master: ")
        if master_pw != master_pw_confirm:
            print("Passwords are different, please try again!")
    print("[+] Master password set up successful")
    return master_pw

import json

def gen_user_key_wrapped(master_key: bytes):

    user_key = secrets.token_bytes(32)

    nonce = os.urandom(12)

    user_key_enc = AESGCM(master_key).encrypt(nonce, user_key, None)

    return base64.b64encode(user_key_enc).decode(), base64.b64encode(nonce).decode()



def setup_authjson(master_pw: str, root: Path) -> bool:
    content["password_hash"] = ph.hash(master_pw)
    master_key, salt_master_key = derive_master_key(master_pw)
    content["kdf_salt"] = salt_master_key


    user_key_wrapped, salt_user_key = gen_user_key_wrapped(master_key)
    content["wrapped_user_key"] = user_key_wrapped
    content["user_key_nonce"] =  salt_user_key
    content["nonce_index"] = base64.b64encode(os.urandom(12)).decode()
    data = serialize_auth_data(content)
    content["hmac_tag"] = base64.b64encode(
        compute_auth_integrity_hmac(master_key, b"auth.json mac", data)
    ).decode()
    with open(root / "auth.json", "wb") as file:
        file.write(serialize_auth_data(content))

    create_index(master_pw)

    return True


def create_index(master_pw: str):

    with open(Path.home() / ".superlock" / "auth.json", "r") as file:
        auth = file.read()
        auth = json.loads(auth)


    key, salt = derive_master_key(master_pw, get_mk_salt())
    user_key = get_user_key(key)
    nonce = get_auth("nonce_index")

    index = json.dumps({}).encode()

    with open(Path.home() / ".superlock" / "index.enc", "wb") as file:
        enc = AESGCM(user_key).encrypt(nonce,index, None)
        file.write(enc)
    

        
