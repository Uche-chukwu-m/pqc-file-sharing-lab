"""The "cloud": a local folder that stores certificates and packages.

It is untrusted. It can read the routing header, and it is free to swap, edit,
replay or delete anything it stores; the clients must catch all of that.

    <root>/certs/<user>.json
    <root>/inbox/<user>/<file_id>.pkg
"""

import json
import re
from pathlib import Path

from .signed_package import read_header

_SAFE_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")


def _safe(name) -> str:
    # Names come from untrusted headers; never let them escape the cloud folder.
    if not isinstance(name, str) or not _SAFE_NAME.fullmatch(name):
        raise KeyError(name)
    return name


class CloudFolder:
    def __init__(self, root):
        self.root = Path(root)

    def put_cert(self, cert: dict) -> None:
        path = self.root / "certs" / f"{_safe(cert['body']['user_id'])}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cert, indent=2))

    def get_cert(self, user_id: str) -> dict:
        path = self.root / "certs" / f"{_safe(user_id)}.json"
        try:
            return json.loads(path.read_text())
        except FileNotFoundError:
            raise KeyError(user_id) from None

    def upload(self, package: bytes) -> Path:
        header = read_header(package)
        path = self.root / "inbox" / _safe(header["recipient"]) / f"{_safe(header['file_id'])}.pkg"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(package)
        return path

    def inbox(self, user_id: str) -> list[Path]:
        return sorted((self.root / "inbox" / _safe(user_id)).glob("*.pkg"))
