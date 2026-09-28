#import argon2-cffi
from getpass import getpass
from .log import logger
import os
from pathlib import Path
from .auth import setup_authjson
from .crypto import get_user_key, get_mk_salt
from .auth import derive_master_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def init():
    try:
        print("CTRL + C anytime to reset initialization and abort")

        root = create_superlock_root()

        master_pw = set_masterpw()
        setup_authjson(master_pw, root)

        create_index()

    except KeyboardInterrupt:
        logger.info("Setup and Initialization aborted and reset")



def create_superlock_root():
    try:
        superlock_dir = Path.home() / ".superlock"
        Path.mkdir(superlock_dir, exist_ok=True)

        Path.mkdir(superlock_dir / "vault", exist_ok=True)
        Path.mkdir(superlock_dir / "keys", exist_ok=True)

        logger.info(f"{superlock_dir} successfully created")
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
    print("Master password set up successful")
    return master_pw

import json

def create_index():

    with open(Path.home() / ".superlock" / "auth.json", "r") as file:
        auth = file.read()
        auth = json.loads(auth)


    key, salt = derive_master_key("test", get_mk_salt())
    user_key = get_user_key(key)
    nonce = os.urandom(12)

    with open(Path.home() / ".superlock" / "index.enc", "wb+") as file:
        data = file.read()
        enc = AESGCM(user_key).encrypt(nonce,data, None)
        file.write(enc)
    

        

