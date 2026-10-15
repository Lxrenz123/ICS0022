from .crypto import *
import os

vault = root / "vault"

def delete(filename: str):
    filepath = lookup_index(filename=filename)

    if os.path.exists(vault / filepath):
        os.remove(vault / filepath)
        remove_from_index()
    else:
        print("The file does not exist in your vault")
    

def remove_from_index():
    pass