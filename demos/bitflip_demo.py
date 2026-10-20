"""Act 1 vs Acts 2-3: the cloud edits an invoice from $100 to $900.

    python -m demos.bitflip_demo

The attacker never learns the key. They only need to know (or guess) where the
amount sits in the file, which is realistic for standard documents like invoices.

CBC decrypts each block as  P[i] = AES_decrypt(C[i]) XOR C[i-1].  So XOR-ing a
value into ciphertext block i-1 XORs the same value into plaintext block i. Block
i-1 turns to garbage, but Version A checks nothing, so it accepts the result.
"""

from cryptography.exceptions import InvalidTag

from pqcshare import version_a, version_b
from pqcshare.encoding import canonical_json, lp
from pqcshare.pki import Identity, TrustAuthority
from pqcshare.signed_package import MAGIC, PackageRejected, open_package, parse_package, seal
from pqcshare.suites import get_suite

from .make_samples import INVOICE

BLOCK = 16
ORIGINAL, FORGED = b"$100", b"$900"


def flip(data: bytes, position: int, delta: bytes) -> bytes:
    out = bytearray(data)
    for i, d in enumerate(delta):
        out[position + i] ^= d
    return bytes(out)


def show(label: str, text: bytes) -> None:
    print(f"    {label}: {text[:BLOCK * 2]!r}")


def main() -> None:
    plaintext = INVOICE.encode()
    target = plaintext.index(ORIGINAL)            # offset of "$100" in block 1
    delta = bytes(a ^ b for a, b in zip(ORIGINAL, FORGED))

    print("Act 1 - Version A (AES-CBC, fixed key and IV, no integrity check)")
    stored = version_a.encrypt(plaintext)
    tampered = flip(stored, target - BLOCK, delta)  # edit the block BEFORE the amount
    restored = version_a.decrypt(tampered)
    show("original", plaintext)
    show("restored", restored)
    print(f"    -> ACCEPTED. Amount now reads {FORGED.decode()}; only block 0 is garbled.\n")

    print("Act 2 - Version B v1 (ML-KEM-768 + AES-256-GCM)")
    pk, sk = get_suite("pq").kem_keygen()
    package = version_b.encrypt(plaintext, pk)
    aes_start = 4 + 1088 + 12                       # length field + KEM ciphertext + nonce
    try:
        version_b.decrypt(flip(package, aes_start + target, delta), sk)
        print("    -> ACCEPTED (this should not happen)\n")
    except InvalidTag:
        print("    -> REJECTED: AES-GCM tag check failed.\n")

    print("Act 3 - Version B v2 (adds ML-DSA certificates and signatures)")
    ta = TrustAuthority.generate("pq")
    alice, bob = Identity.generate("alice"), Identity.generate("bob")
    certs = {"alice": ta.issue(alice), "bob": ta.issue(bob)}
    meta = canonical_json({"category": "financial", "filename": "financial_invoice.txt"})
    package = seal(plaintext, sender=alice, recipient_cert=certs["bob"], ta_pk=ta.sig_pk,
                   filename="financial_invoice.txt", category="financial")
    header, kem_ct, nonce, ciphertext, signature = parse_package(package)
    # GCM encrypts like a stream cipher, so this edit WOULD turn $100 into $900
    # exactly; only the tag and the signature stop it.
    amount_at = 4 + len(meta) + 4 + target       # inside lp(meta) + lp(data)
    ciphertext = flip(ciphertext, amount_at, delta)
    tampered = MAGIC + b"".join(lp(f) for f in (header, kem_ct, nonce, ciphertext, signature))
    try:
        open_package(tampered, recipient=bob, ta_pk=ta.sig_pk,
                     fetch_cert=certs.__getitem__, seen_ids=set())
        print("    -> ACCEPTED (this should not happen)")
    except PackageRejected as exc:
        print(f"    -> REJECTED: {exc.reason} (checked before any decryption).")


if __name__ == "__main__":
    main()
