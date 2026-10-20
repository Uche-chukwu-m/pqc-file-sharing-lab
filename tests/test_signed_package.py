"""Version B v2, run with both the post-quantum and the classical suite."""

import time

import pytest

from pqcshare.encoding import lp
from pqcshare.pki import CertificateError, Identity, TrustAuthority
from pqcshare.signed_package import MAGIC, PackageRejected, open_package, parse_package, seal

DATA = b"FICTIONAL LAB REPORT - hemoglobin 13.9 g/dL"


class World:
    def __init__(self, suite):
        self.ta = TrustAuthority.generate(suite)
        self.users = {name: Identity.generate(name, suite) for name in ("alice", "bob", "mallory")}
        self.certs = {name: self.ta.issue(user) for name, user in self.users.items()}

    def seal(self, data=DATA, sender="alice", to="bob", **kwargs):
        return seal(data, sender=self.users[sender], recipient_cert=self.certs[to], ta_pk=self.ta.sig_pk,
                    filename="lab_report.txt", category="medical", **kwargs)

    def open(self, package, as_user="bob", seen=None, **kwargs):
        return open_package(package, recipient=self.users[as_user], ta_pk=self.ta.sig_pk,
                            fetch_cert=self.certs.__getitem__,
                            seen_ids=set() if seen is None else seen, **kwargs)


@pytest.fixture(scope="module", params=["pq", "classical"])
def world(request):
    return World(request.param)


def rebuild(fields):
    return MAGIC + b"".join(lp(f) for f in fields)


def test_round_trip(world):
    opened = world.open(world.seal())
    assert (opened.data, opened.sender, opened.filename, opened.category) == \
        (DATA, "alice", "lab_report.txt", "medical")


def test_cloud_cannot_see_filename_or_category(world):
    header = parse_package(world.seal())[0]
    assert b"lab_report" not in header and b"medical" not in header


def test_padding_hides_exact_size(world):
    small, large = world.seal(b"a" * 10, pad_to=1024), world.seal(b"a" * 900, pad_to=1024)
    assert len(parse_package(small)[3]) == len(parse_package(large)[3]) == 1024 + 16
    assert world.open(large).data == b"a" * 900


@pytest.mark.parametrize("field", range(5), ids=["header", "kem_ct", "nonce", "ciphertext", "signature"])
def test_any_changed_field_is_rejected(world, field):
    fields = list(parse_package(world.seal()))
    changed = bytearray(fields[field])
    changed[len(changed) // 2] ^= 0x01
    fields[field] = bytes(changed)
    with pytest.raises(PackageRejected):
        world.open(rebuild(fields))


def test_every_single_bit_flip_position_sampled(world):
    package = world.seal()
    for i in range(0, len(package), 37):
        tampered = bytearray(package)
        tampered[i] ^= 0x80
        with pytest.raises(PackageRejected):
            world.open(bytes(tampered))


def test_rejection_message_is_generic(world):
    with pytest.raises(PackageRejected) as info:
        world.open(world.seal()[:-1])
    assert str(info.value) == "package rejected"


def test_only_the_recipient_can_open(world):
    with pytest.raises(PackageRejected) as info:
        world.open(world.seal(), as_user="mallory")
    assert info.value.reason == "addressed to someone else"


def test_replay_is_rejected(world):
    package, seen = world.seal(), set()
    world.open(package, seen=seen)
    with pytest.raises(PackageRejected) as info:
        world.open(package, seen=seen)
    assert info.value.reason.startswith("replay")


def test_sender_refuses_a_certificate_the_ta_did_not_sign(world):
    forged = {"body": dict(world.certs["bob"]["body"]), "ta_sig": world.certs["bob"]["ta_sig"]}
    forged["body"]["kem_pk"] = world.certs["mallory"]["body"]["kem_pk"]
    with pytest.raises(CertificateError):
        seal(DATA, sender=world.users["alice"], recipient_cert=forged, ta_pk=world.ta.sig_pk,
             filename="x.txt", category="medical")


def test_expired_sender_certificate_is_rejected(world):
    package = world.seal()
    with pytest.raises(PackageRejected) as info:
        world.open(package, now=time.time() + 400 * 86400)
    assert "certificate" in info.value.reason


def test_unknown_sender_is_rejected(world):
    package = world.seal()
    with pytest.raises(PackageRejected):
        open_package(package, recipient=world.users["bob"], ta_pk=world.ta.sig_pk,
                     fetch_cert={}.__getitem__, seen_ids=set())
