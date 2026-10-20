import pytest

from demos.make_samples import INVOICE
from pqcshare import version_a


def test_round_trip():
    data = b"fictional data " * 10
    assert version_a.decrypt(version_a.encrypt(data)) == data


def test_fixed_iv_leaks_equal_files():
    # Same key + same IV: encrypting the same file twice gives the same bytes.
    assert version_a.encrypt(b"same file") == version_a.encrypt(b"same file")


def test_bit_flip_is_accepted():
    plaintext = INVOICE.encode()
    stored = bytearray(version_a.encrypt(plaintext))
    at = plaintext.index(b"$100") + 1 - 16      # the "1", one block earlier
    stored[at] ^= ord("1") ^ ord("9")
    restored = version_a.decrypt(bytes(stored))
    assert b"Amount: $900.00" in restored


def test_bad_padding_raises():
    # Version A's only "check": a broken padding byte raises; a broken block in the middle does not.
    stored = bytearray(version_a.encrypt(b"x" * 20))
    stored[-17] ^= 0x01
    with pytest.raises(ValueError):
        version_a.decrypt(bytes(stored))
