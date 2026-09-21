import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

file_format = logging.Formatter(
        fmt="{asctime} - {levelname} - {message} - {module}",
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
file_handler = logging.FileHandler(filename="logs", mode="a", encoding="utf-8")
file_handler.setFormatter(file_format)
file_handler.setLevel(logging.INFO)

logger.addHandler(console_handler)
logger.addHandler(file_handler)



# tests
# logger.debug("hi")