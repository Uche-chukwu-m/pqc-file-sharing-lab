"""Sign the result reports, or check them before trusting them (Act 5).

    python -m ml.sign_results sign       # approver signs every file in results/
    python -m ml.sign_results verify     # refuse if any report was changed or added

The signature lives in results/results.sig.json.
"""

import argparse
import json
import sys
from pathlib import Path

from pqcshare.cloud import CloudFolder
from pqcshare.pki import Identity, TrustAuthority

from .signing import ArtifactRejected, sign_artifacts, verify_artifacts

RESULTS = Path(__file__).resolve().parent.parent / "results"
SIG_FILE = RESULTS / "results.sig.json"
PURPOSE = "approved experiment results"
APPROVERS = {"approver"}


def report_files() -> list[Path]:
    return sorted(p for p in RESULTS.iterdir() if p.is_file() and p != SIG_FILE and p.suffix in (".md", ".csv"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("action", choices=("sign", "verify"))
    parser.add_argument("--lab", default="lab")
    parser.add_argument("--signer", default="approver")
    args = parser.parse_args()
    lab = Path(args.lab)
    ta = TrustAuthority.load(lab / "ta.json")

    if args.action == "sign":
        signer = Identity.load(lab / "users" / args.signer / "identity.json")
        signed = sign_artifacts(report_files(), signer, PURPOSE, RESULTS)
        SIG_FILE.write_text(json.dumps(signed, indent=2))
        print(f"{args.signer} signed {len(signed['manifest']['files'])} files -> {SIG_FILE.name}")
        return

    try:
        manifest, verified = verify_artifacts(json.loads(SIG_FILE.read_text()), RESULTS, ta_pk=ta.sig_pk,
                                              suite=ta.suite, fetch_cert=CloudFolder(lab / "cloud").get_cert,
                                              trusted_signers=APPROVERS, purpose=PURPOSE)
    except (ArtifactRejected, OSError, ValueError) as exc:
        sys.exit(f"REFUSED: {getattr(exc, 'reason', exc)}")
    unsigned = {p.name for p in report_files()} - set(verified)
    if unsigned:
        sys.exit(f"REFUSED: not covered by the signature: {', '.join(sorted(unsigned))}")
    print(f"all {len(verified)} result files verified (signed by {manifest['signer']})")


if __name__ == "__main__":
    main()
