"""Imports liboqs-python, pointing it at a system liboqs when one is installed.

If liboqs-python cannot find liboqs, it tries to download and build it with cmake
on first import. Installing it with Homebrew (`brew install liboqs`) avoids that.
On other systems, set OQS_INSTALL_PATH to the liboqs install prefix.
"""

import logging
import os

for _prefix in ("/opt/homebrew/opt/liboqs", "/usr/local/opt/liboqs"):
    if "OQS_INSTALL_PATH" not in os.environ and os.path.isdir(_prefix):
        os.environ["OQS_INSTALL_PATH"] = _prefix

# liboqs-python logs a faulthandler notice on every import; hide just that line.
logging.getLogger("oqs.oqs").addFilter(lambda record: "faulthandler" not in record.getMessage())

import oqs  # noqa: E402

__all__ = ["oqs"]
