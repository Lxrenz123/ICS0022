import logging
from pathlib import Path
import os

root = Path.home() / ".superlock"

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

file_format = logging.Formatter(
        fmt="{asctime} - {levelname} - {message}",
        style="{",
        datefmt="%a %d.%m.%Y %X"

)
console_format = logging.Formatter(
        fmt="[{levelname}] - {message}",
        style="{"
)

# Console Handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(console_format)

# File Handler
if root.exists(follow_symlinks=False):
        file_handler = logging.FileHandler(filename=f"{Path.home() / ".superlock" / "logs.txt"}", mode="a", encoding="utf-8")
        os.chmod(Path.home() / ".superlock" / "logs.txt", 0o600)
        file_handler.setFormatter(file_format)
        file_handler.setLevel(logging.INFO)
        logger.addHandler(file_handler)
logger.addHandler(console_handler)



