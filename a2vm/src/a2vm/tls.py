# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The TLS of A2VM's HTTP clients: which CAs to trust, which client certificate to present.

One way for every client (v0.23.17). httpx 0.28 takes `verify=<path>` and `cert=(cert, key)` as
deprecated shortcuts, and with a path in `verify` it returns the context before loading `cert`: the
client certificate was never sent, and a reverse proxy that asks for one answered 403 to everything
(found on a Cyberwatch master in integration). Here the certificate always goes into the SSL context
given as `verify`; `cert=` and a path in `verify` are kept out of the code by a test.
"""

from __future__ import annotations

import os
import ssl
from typing import Any


def verify(ca_file: str | None = None, cert_file: str | None = None, key_file: str | None = None) -> Any:
    """What to give httpx as `verify`.

    - `ca_file`: only this CA is trusted (as `verify=<path>` did);
    - else the CAs httpx trusts by default: `SSL_CERT_FILE` or `SSL_CERT_DIR` (the proxy's bundle in
      the cluster), else certifi's;
    - `cert_file` and `key_file`, both or none: the client certificate, loaded into the context.

    True when there is nothing to change (httpx's default)."""
    if bool(cert_file) != bool(key_file):
        raise ValueError("a client certificate needs both its certificate and its key")
    if not ca_file and not cert_file:
        return True
    ctx = ssl.create_default_context(cafile=ca_file) if ca_file else default_context()
    if cert_file:
        ctx.load_cert_chain(cert_file, key_file)
    return ctx


def default_context() -> ssl.SSLContext:
    """The context httpx builds for `verify=True`."""
    if os.environ.get("SSL_CERT_FILE"):
        return ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
    if os.environ.get("SSL_CERT_DIR"):
        return ssl.create_default_context(capath=os.environ["SSL_CERT_DIR"])
    import certifi

    return ssl.create_default_context(cafile=certifi.where())
