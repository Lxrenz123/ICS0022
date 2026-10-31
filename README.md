# SuperLock

SuperLock is a secure command-line file encryption and management tool written in Python.

The purpose of the project is to provide a simple way to protect secret files on your system.
## Project Scope

SuperLock provides:
* Secure file encryption and decryption
* A custom encrypted `.sl` file format
* Secure deletion
* Logging 

## Technology

SuperLock is implemented in Python.

External libraries:

* `cryptography` — for all cryptography
* `argon2-cffi` — password hashing and password-based key derivation

## Installation 

#### Requirements:
* Python >= 3.10

Clone the repository:

```bash
git clone https://github.com/Lxrenz123/ICS0022
cd ICS0022
```

From the project directory:
```bash
pipx install .
```

## Usage 


### Initialize SuperLock

```bash
superlock init
```
* creates .superlock in your home directory with all necessary files
* sets your master password used for all operations

### Encrypt a file

```bash
superlock encrypt <file> <name>
```

Encrypts a file and stores it in the SuperLock (.sl) format insinde ~/.superlock/vault/
Name is optional, by default it equals filename


### Decrypt a file

```bash
superlock decrypt <file.sl>
```
Decrypts a SuperLock file after successful integrity verification.


### List stored files

```bash
superlock list
```

Displays files stored in the SuperLock vault without exposing their contents, only displaying name.



### Help

```bash
superlock -h
```

Displays available commands and usage information.



