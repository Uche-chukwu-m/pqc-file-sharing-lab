import pytest
from cryptography.exceptions import InvalidTag

from pqcshare import version_b
from pqcshare.suites import get_suite


@pytest.fixture(scope="module")
def keys():
    return get_suite("pq").kem_keygen()


def test_round_trip(keys):
    pk, sk = keys
    data = b"fictional lab report"
    assert version_b.decrypt(version_b.encrypt(data, pk), sk) == data


def test_package_overhead_is_1120_bytes(keys):
    pk, _ = keys
    assert len(version_b.encrypt(b"x" * 1000, pk)) == 1000 + 4 + 1088 + 12 + 16


@pytest.mark.parametrize("region,offset", [
    ("length field", 3),
    ("KEM ciphertext", 4 + 500),
    ("nonce", 4 + 1088 + 5),
    ("AES ciphertext", 4 + 1088 + 12 + 3),
    ("GCM tag", -1),
])
def test_tampering_is_rejected(keys, region, offset):
    pk, sk = keys
    package = bytearray(version_b.encrypt(b"fictional invoice: $100", pk))
    package[offset] ^= 0x01
    with pytest.raises((InvalidTag, ValueError)):
        version_b.decrypt(bytes(package), sk)
