from .auth import authenticate, derive_master_key
from .crypto import get_mk_salt, lookup_index, remove_from_index
from pathlib import Path

vault = Path.home() / ".superlock" / "vault"

def delete(filename: str):
    master_key, _ = derive_master_key(authenticate(), get_mk_salt())
    filepath = lookup_index(filename, master_key)
    vault_path = vault / filepath

    if vault_path.exists():
        vault_path.unlink()
        remove_from_index(filename, master_key)
        print(f"Successfully deleted {filename}")
    else:
        print("The file does not exist in your vault")

