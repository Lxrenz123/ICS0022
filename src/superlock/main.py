def main():
    import argparse
    from .init import init
    from .crypto import encrypt, decrypt, ls_vault
    from .delete import delete
    from .purge import purge
    from pathlib import Path
    # parser + sub parser for command(encrypt,decrypt,init,delete)
    parser = argparse.ArgumentParser(prog="superlock")
    sub = parser.add_subparsers(dest="action", required=True)

    # init
    sub.add_parser("init")


    # list vault files
    sub.add_parser("list")

    
    # list vault files
    sub.add_parser("purge")


    # superlock encrypt
    enc = sub.add_parser("encrypt")
    enc.add_argument("path", help="file path to the file to encrypt")
    enc.add_argument("name", help="filename to store the encrypted file as in the vault",nargs="?", default=None)


    # superlock decrypt
    dec = sub.add_parser("decrypt")
    dec.add_argument("filename")
    dec.add_argument("--stdout", action="store_true", help="print decrypted content to stdout")


    # superlock delete
    delete_parser = sub.add_parser("delete")
    delete_parser.add_argument("filename", help="filename of the file to delete from the vault")

    args = parser.parse_args()

    if args.action == "init":
        init()
    else:
        if not (Path.home() / ".superlock").is_dir():
            print("SuperLock has not been initialized: superlock init")
            return
        if args.action == "encrypt":
            encrypt(args.path, args.name)
        elif args.action == "decrypt":
            decrypt(args.filename)
        elif args.action == "list":
            ls_vault()
        elif args.action == "delete":
            delete(args.filename)
        elif args.action == "purge":
            purge()

if __name__ == "__main__":
    main()