#import argon2-cffi
from getpass import getpass
from log import logger
import os
from pathlib import Path
from auth import set_pw

def init():
    try:
        print("CTRL + C anytime to reset initialization and abort")

        root = create_superlock_root()

        master_pw = set_masterpw()
        set_pw(master_pw, root / "auth.json")

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

