import os
import secrets
import shutil
import stat
from pathlib import Path

CHUNK = 1024 * 1024


def overwrite_file(path: Path):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode):
        return
    os.chmod(path, 0o600)
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    try:
        remaining = st.st_size
        while remaining > 0:
            n = min(CHUNK, remaining)
            os.write(fd, secrets.token_bytes(n))
            remaining -= n
        os.fsync(fd)
        os.ftruncate(fd, 0)
        os.fsync(fd)
    finally:
        os.close(fd)


def purge() -> bool:
    superlock_dir = Path.home() / ".superlock"
    if superlock_dir.is_symlink() or not superlock_dir.is_dir():
        print("SuperLock directory does not exist (or is a symlink)")
        return False

    confirmation = input(
        f"This will permanently delete {superlock_dir} and all vault files. "
        "Type 'PURGE' to continue: "
    )
    if confirmation != "PURGE":
        print("Purge cancelled")
        return False

    files = [p for p in superlock_dir.rglob("*") if p.is_file() and not p.is_symlink()]
    files.sort(key=lambda p: p.lstat().st_size)

    failed = []
    for p in files:
        try:
            overwrite_file(p)
        except OSError as e:
            failed.append((p, e))

    shutil.rmtree(superlock_dir, ignore_errors=False)

    if failed:
        print(f"Warning: could not overwrite {len(failed)} file(s):")
        for p, e in failed:
            print(f"  {p}: {e}")
    print(f"Purged {superlock_dir}")
    return not failed