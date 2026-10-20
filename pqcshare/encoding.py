"""Byte encodings shared by the package and certificate formats."""

import json


def canonical_json(obj) -> bytes:
    """Encode obj the same way every time, so its signature always verifies."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def lp(data: bytes) -> bytes:
    """Length-prefix a field so field boundaries cannot be shifted."""
    return len(data).to_bytes(4, "big") + data


class Reader:
    """Reads length-prefixed fields and fails on truncated or trailing data."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError("truncated data")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def field(self) -> bytes:
        return self.take(int.from_bytes(self.take(4), "big"))

    def done(self) -> None:
        if self.pos != len(self.data):
            raise ValueError("unexpected trailing data")
