"""Command-line demo of signed, post-quantum file sharing.

    python -m pqcshare.cli setup                       # TA + alice, bob, mallory, approver
    python -m pqcshare.cli send --from alice --to bob --file data/samples/medical_lab_report.txt --category medical
    python -m pqcshare.cli receive --as bob

Lab folder layout (default ./lab, git-ignored because it holds private keys):

    lab/ta.json                      TA private key ("kept offline")
    lab/users/<name>/identity.json   the user's private keys
    lab/users/<name>/trusted_ta.hex  the TA public key the user pins
    lab/users/<name>/seen_ids.json   file IDs already accepted (replay check)
    lab/users/<name>/received/       decrypted files
    lab/users/<name>/downloaded/     accepted packages, moved out of the cloud inbox
    lab/users/<name>/rejected/       rejected packages, kept for inspection
    lab/cloud/                       the untrusted cloud folder
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

from .cloud import CloudFolder
from .pki import CertificateError, Identity, TrustAuthority
from .signed_package import PackageRejected, open_package, seal

CATEGORIES = ("medical", "legal", "personal", "financial")


def _user_dir(lab: Path, name: str) -> Path:
    return lab / "users" / name


def _move(path: Path, folder: Path) -> None:
    # Like downloading email: processed packages leave the cloud inbox.
    folder.mkdir(parents=True, exist_ok=True)
    shutil.move(path, folder / path.name)


def cmd_setup(args) -> None:
    lab = Path(args.lab)
    if lab.exists():
        if not args.force:
            sys.exit(f"{lab} already exists; pass --force to wipe it and start over")
        shutil.rmtree(lab)
    ta = TrustAuthority.generate(args.suite)
    ta.save(lab / "ta.json")
    cloud = CloudFolder(lab / "cloud")
    for name in args.users:
        identity = Identity.generate(name, args.suite)
        identity.save(_user_dir(lab, name) / "identity.json")
        (_user_dir(lab, name) / "trusted_ta.hex").write_text(ta.sig_pk.hex())
        cloud.put_cert(ta.issue(identity))
        print(f"created {name}: certificate signed by the TA and published to the cloud")
    print(f"suite: {args.suite}; lab folder: {lab}")


def cmd_send(args) -> None:
    lab = Path(args.lab)
    sender = Identity.load(_user_dir(lab, args.sender) / "identity.json")
    ta_pk = bytes.fromhex((_user_dir(lab, args.sender) / "trusted_ta.hex").read_text())
    cloud = CloudFolder(lab / "cloud")
    source = Path(args.file)
    try:
        package = seal(source.read_bytes(), sender=sender, recipient_cert=cloud.get_cert(args.to),
                       ta_pk=ta_pk, filename=source.name, category=args.category, pad_to=args.pad)
    except (CertificateError, KeyError) as exc:
        sys.exit(f"refused to send: recipient certificate not trusted ({exc})")
    path = cloud.upload(package)
    print(f"{args.sender} -> {args.to}: {source.name} ({source.stat().st_size} B) "
          f"uploaded as {path.name} ({len(package)} B)")


def cmd_receive(args) -> None:
    lab = Path(args.lab)
    home = _user_dir(lab, args.recipient)
    me = Identity.load(home / "identity.json")
    ta_pk = bytes.fromhex((home / "trusted_ta.hex").read_text())
    seen_path = home / "seen_ids.json"
    seen = set(json.loads(seen_path.read_text())) if seen_path.exists() else set()
    out_dir = home / "received"
    cloud = CloudFolder(lab / "cloud")

    packages = cloud.inbox(args.recipient)
    if not packages:
        print(f"{args.recipient}: inbox empty")
    for pkg in packages:
        try:
            opened = open_package(pkg.read_bytes(), recipient=me, ta_pk=ta_pk,
                                  fetch_cert=cloud.get_cert, seen_ids=seen)
        except PackageRejected as exc:
            # The user sees only "rejected"; the reason is printed here for the demo.
            print(f"REJECTED {pkg.name}  [{exc.reason}]")
            _move(pkg, home / "rejected")
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        # The filename came from the sender: keep only its last component.
        out = out_dir / (Path(opened.filename).name or opened.file_id)
        out.write_bytes(opened.data)
        print(f"ACCEPTED {pkg.name}  from {opened.sender}: {opened.filename} "
              f"[{opened.category}] -> {out}")
        _move(pkg, home / "downloaded")
    seen_path.write_text(json.dumps(sorted(seen)))


def _pad_policy(value: str) -> int | str:
    return value if value in ("pow2", "padme") else int(value)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(prog="pqcshare", description=__doc__.split("\n")[0])
    parser.add_argument("--lab", default="lab", help="lab folder (default: ./lab)")
    sub = parser.add_subparsers(required=True)

    p = sub.add_parser("setup", help="create the Trust Authority and users")
    p.add_argument("--suite", choices=("pq", "classical"), default="pq")
    p.add_argument("--users", nargs="+", default=["alice", "bob", "mallory", "approver"])
    p.add_argument("--force", action="store_true", help="wipe an existing lab folder")
    p.set_defaults(func=cmd_setup)

    p = sub.add_parser("send", help="encrypt, sign and upload a file")
    p.add_argument("--from", dest="sender", required=True)
    p.add_argument("--to", required=True)
    p.add_argument("--file", required=True)
    p.add_argument("--category", choices=CATEGORIES, required=True)
    p.add_argument("--pad", type=_pad_policy, default=None,
                   help="padding policy: a byte count (round up to a multiple), pow2, or padme")
    p.set_defaults(func=cmd_send)

    p = sub.add_parser("receive", help="verify and decrypt everything in a user's inbox")
    p.add_argument("--as", dest="recipient", required=True)
    p.set_defaults(func=cmd_receive)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
