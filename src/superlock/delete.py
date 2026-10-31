from .auth import authenticate, derive_master_key
from .crypto import get_mk_salt, lookup_index, remove_from_index
from pathlib import Path

vault = Path.home() / ".superlock" / "vault"
from .purge import overwrite_file

def delete(filename: str) -> bool:
    master_key, salt = derive_master_key(authenticate(), get_mk_salt())

    filepath = lookup_index(filename, master_key)
    if filepath is None:
        print("The file does not exist in your vault")
        return False

    vault_root = vault.resolve()
    vault_path = (vault_root / filepath)

    if not vault_path.parent.resolve().is_relative_to(vault_root):
        print("Invalid path in index; refusing to delete")
        return False


    remove_from_index(filename, master_key)


    try:
        overwrite_file(vault_path)   
    except FileNotFoundError:
        print("vault file was already missing; index entry removed")
        return True
    except OSError as e:
        print(f"could not overwrite {filename}: {e}")

    try:
        vault_path.unlink()
    except FileNotFoundError:
        pass

    print(f"Deleted {filename}")
    return True