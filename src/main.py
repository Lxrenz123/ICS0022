import argparse
from init import init
# parser + sub parser for command(encrypt,decrypt,init,delete)
parser = argparse.ArgumentParser(prog="superlock")
sub = parser.add_subparsers(dest="action", required=True)

# init
sub.add_parser("init")


# list vault files
sub.add_parser("list")


# superlock encrypt
enc = sub.add_parser("encrypt")
enc.add_argument("path", help="file path to the file to encrypt")


# superlock decrypt
dec = sub.add_parser("decrypt")
dec.add_argument("filename")
dec.add_argument("--stdout", action="store_true", help="print decrypted content to stdout")


# superlock delete
delete = sub.add_parser("delete")
delete.add_argument("filename", help="filename of the file to delete from the vault")

args = parser.parse_args()

if args.action == "encrypt":
    print("encryption brurbubrubr")
elif args.action == "init":
    init()