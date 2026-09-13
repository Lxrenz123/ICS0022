# SuperLock

SuperLock is a secure command-line file encryption and management tool written in Python.

The purpose of the project is to provide a simple way to protect secret files on your system.
## Project Scope

SuperLock will provide:
* Secure file encryption and decryption
* A custom encrypted `.sl` file format
* Per-user file ownership and access control
* Secure deletion
* Logging of activity
* and more

## Technology

SuperLock will be implemented in Python.

Planned external libraries:

* `cryptography` — for all cryptography
* `argon2-cffi` — password hashing and password-based key derivation


## Planned Command-Line Interface

### Initialize SuperLock

```bash
superlock init
```

Creates the initial SuperLock configuration and sets up the user account.

### Encrypt a file

```bash
superlock encrypt <file>
```

Encrypts a file and stores it in the SuperLock (.sl) format.


### Decrypt a file

```bash
superlock decrypt <file.sl>
```
Decrypts a SuperLock file after successful authentication and integrity verification.


### List stored files

```bash
superlock list
```

Displays files stored in the SuperLock vault without exposing their contents, only displaying metadata.

### Show file information

```bash
superlock info <file.sl>
```

Displays non-sensitive information about a SuperLock container.

### Help

```bash
superlock -h
```

Displays available commands and usage information.


## Installation

Clone the repository:

```bash
git clone <repository-url>
cd superlock
```

From the project directory:
```bash
pip install .
```
