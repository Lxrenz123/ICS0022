"""
Covers: encryption/decryption correctness, secure deletion, authentication failure
paths, input-validation edge cases. Run: pytest -v
"""
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from superlock import auth, crypto, delete, purge

PASSPHRASE = "password"
MARKER = b"TOP-SECRET-MARKER-0123456789"
MODULES = [auth, crypto, delete, purge]


# ----------------------------------------------------------------------------
# Fixtures: isolated HOME, patched prompts, freshly initialised vault
# ----------------------------------------------------------------------------
@pytest.fixture
def env(sandbox, run_setup):
    """Reuse the shared isolated HOME and initialize a real vault."""
    sandbox.root.mkdir(mode=0o700)
    sandbox.vault.mkdir(mode=0o700)
    run_setup()
    return sandbox


def make_file(env, name="plain.txt", content=MARKER):
    path = env.home / name
    path.write_bytes(content)
    return path


def decrypted(name, capsys):
    capsys.readouterr()
    return crypto.decrypt(name, output_path=Path("/tmp") / "unused-decrypted-name")


def vault_files(env):
    return sorted(env.vault.glob("*.sl"))


# ----------------------------------------------------------------------------
# 1. Encryption / decryption correctness
# ----------------------------------------------------------------------------
@pytest.mark.parametrize("content", [b"", b"\x00", MARKER, os.urandom(70_000)],
                         ids=["empty", "one_byte", "text", "binary_70k"])
def test_roundtrip_returns_identical_bytes(env, capsys, content):
    src = make_file(env, content=content)
    crypto.encrypt(str(src))
    assert decrypted(src.name, capsys) == content


def test_vault_file_does_not_contain_plaintext(env):
    crypto.encrypt(str(make_file(env)))
    (blob,) = vault_files(env)
    assert MARKER not in blob.read_bytes()


def test_decrypt_recovers_original_file(env):
    src = make_file(env, content=b"recovered contents")
    crypto.encrypt(str(src), "recovered.txt")

    recovered = env.home / "restored.txt"
    crypto.decrypt("recovered.txt", output_path=recovered)

    assert recovered.read_bytes() == b"recovered contents"


@pytest.mark.parametrize("pos", [0, 8, 24, -1, -16])
def test_modified_vault_file_is_rejected(env, capsys, pos):
    src = make_file(env, content=MARKER * 20)
    crypto.encrypt(str(src))
    (blob,) = vault_files(env)
    data = bytearray(blob.read_bytes())
    data[pos] ^= 0x01
    blob.write_bytes(bytes(data))
    capsys.readouterr()
    with pytest.raises(SystemExit):
        crypto.decrypt(src.name)
    assert MARKER.decode() not in capsys.readouterr().out


def test_wrong_passphrase_cannot_decrypt(env):
    src = make_file(env)
    crypto.encrypt(str(src))
    env.passphrase = "wrong passphrase"
    with pytest.raises(SystemExit):
        crypto.decrypt(src.name)


# ----------------------------------------------------------------------------
# 2. Secure deletion
# ----------------------------------------------------------------------------
def test_overwrite_file_erases_contents(tmp_path):
    target = tmp_path / "secret.bin"
    target.write_bytes(b"sensitive contents")
    purge.overwrite_file(target)
    assert target.read_bytes() == b""


def test_delete_removes_ciphertext_and_index_entry(env):
    src = make_file(env)
    crypto.encrypt(str(src))
    assert delete.delete(src.name) is True
    assert vault_files(env) == []
    assert src.name not in crypto.decrypt_index()


def test_deleted_file_cannot_be_decrypted(env):
    src = make_file(env)
    crypto.encrypt(str(src))
    delete.delete(src.name)
    with pytest.raises(SystemExit):
        crypto.decrypt(src.name)


# ----------------------------------------------------------------------------
# 3. Authentication failure paths
# ----------------------------------------------------------------------------
def test_correct_passphrase_authenticates(env):
    assert auth.authenticate() is not None


@pytest.mark.parametrize("wrong", ["wrong passphrase", ""])
def test_wrong_passphrase_is_rejected(env, wrong):
    env.passphrase = wrong
    with pytest.raises(SystemExit):
        auth.authenticate()


def test_modified_auth_json_is_rejected(env):
    path = env.root / "auth.json"
    content = json.loads(path.read_text())
    tag = content["hmac_tag"]
    content["hmac_tag"] = ("B" if tag[0] != "B" else "C") + tag[1:]
    path.write_text(json.dumps(content))
    with pytest.raises(SystemExit):
        auth.authenticate()


@pytest.mark.parametrize("raw", [b"", b"{not json"], ids=["empty", "malformed"])
def test_damaged_auth_json_fails_cleanly(env, raw):
    (env.root / "auth.json").write_bytes(raw)
    with pytest.raises(SystemExit):
        auth.authenticate()


# ----------------------------------------------------------------------------
# 4. Input-validation edge cases
# ----------------------------------------------------------------------------
def test_encrypt_rejects_missing_path(env):
    with pytest.raises(SystemExit):
        crypto.encrypt(str(env.home / "does-not-exist"))
    assert vault_files(env) == []


def test_encrypt_rejects_directory(env):
    with pytest.raises(SystemExit):
        crypto.encrypt(str(env.home))
    assert vault_files(env) == []


@pytest.mark.skipif(os.name == "nt", reason="symlinks need POSIX")
def test_encrypt_rejects_symlink(env):
    target = make_file(env, "secret.txt", b"secret")
    link = env.home / "link.txt"
    link.symlink_to(target)
    with pytest.raises(SystemExit):
        crypto.encrypt(str(link))
    assert vault_files(env) == []


@pytest.mark.parametrize("name", ["", "never-encrypted.txt", "../../etc/passwd"])
def test_decrypt_rejects_unknown_names(env, name):
    with pytest.raises(SystemExit):
        crypto.decrypt(name)