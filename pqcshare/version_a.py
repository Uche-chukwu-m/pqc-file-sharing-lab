"""Version A: the deliberately weak design (Act 1). VULNERABLE - CLASSROOM DEMO ONLY.

Taken from the rough draft's Version A:
  * hard-coded key, so anyone with the source code can decrypt everything
  * the same CBC IV every time, so identical starting blocks give identical ciphertext
  * no authentication, so ciphertext can be edited without detection (bit flipping)
  * the only failure it can report is bad padding, which catches random damage by
    luck, never on purpose
"""

from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Bad practice: key and IV are embedded and reused.
KEY = b"0123456789abcdef0123456789abcdef"
IV = b"0123456789abcdef"


def encrypt(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(KEY), modes.CBC(IV)).encryptor()
    return enc.update(padded) + enc.finalize()


def decrypt(ciphertext: bytes) -> bytes:
    """Raises ValueError on bad padding; nothing else is ever checked."""
    dec = Cipher(algorithms.AES(KEY), modes.CBC(IV)).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def vulnerable_store(source, stored) -> None:
    Path(stored).write_bytes(encrypt(Path(source).read_bytes()))


def vulnerable_restore(stored, output) -> None:
    Path(output).write_bytes(decrypt(Path(stored).read_bytes()))
