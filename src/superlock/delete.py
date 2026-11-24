from .auth import authenticate, derive_master_key
from .crypto import lookup_index, remove_from_index, get_auth
from pathlib import Path
from .log import logger
import sys
vault = Path.home() / ".superlock" / "vault"
from .purge import overwrite_file


def delete(filename: str) -> bool:

    master_key, _ = derive_master_key(authenticate(), get_auth("kdf_salt"))

    filepath = lookup_index(filename, master_key)
    if filepath is None:
        logger.error(f"Deletion failed: {filename} not found")
        sys.exit(1)

    vault_root = vault.resolve()
    vault_path = (vault_root / filepath)

    if not vault_path.parent.resolve().is_relative_to(vault_root):
        print("Invalid path in index; refusing to delete")
        return False


    remove_from_index(filename, master_key)

    try:
        overwrite_file(vault_path)   
    except FileNotFoundError:
        logger.error(f"Deletion failed: {filename} not found")
        sys.exit(1)


    try:
        vault_path.unlink()
    except FileNotFoundError:
        pass

    logger.info("Successfully deleted")
    
    return True