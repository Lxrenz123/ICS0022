from pathlib import Path
import shutil


def purge():
    superlock_dir = Path.home() / ".superlock"
    if not superlock_dir.is_dir():
        print("SuperLock directory does not exist")
        return

    confirmation = input(
        f"This will permanently delete {superlock_dir} and all vault files. "
        "Type 'PURGE' to continue: "
    )
    if confirmation != "PURGE":
        print("Purge cancelled")
        return

    shutil.rmtree(superlock_dir)
    print(f"Purged {superlock_dir}")