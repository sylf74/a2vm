#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Values of the conversational search for the chart, written by the job deploy-k8s (stdlib only).

Reads the tenant project's variables from the environment and writes a values file (JSON, which
Helm reads as YAML): the host, the ingress, the LLM endpoints and where they are for the
NetworkPolicy. Endpoints given by name are resolved here, in the job, to their addresses.

    A2VM_CHAT_HOST                  host of the chat (required to deploy it)
    A2VM_LLM_BASE_URL, A2VM_LLM_MODEL   the tenant's approved endpoints (comma-separated) and model
    A2VM_CHAT_LLM_EGRESS            optional: `cidr:port,...`, instead of resolving the endpoints
    A2VM_CHAT_ALLOW                 optional: the analysts' networks (CIDR, comma-separated)
    A2VM_CHAT_ADMIN_EMAIL           optional: login of the first admin
    A2VM_CHAT_RETENTION_DAYS        optional: chats unchanged for longer are deleted (default 30, 0: kept)
    A2VM_CHAT_INGRESS_CONTROLLER, A2VM_CHAT_INGRESS_CLASS, A2VM_CHAT_TLS_SECRET,
    A2VM_CHAT_CLUSTER_ISSUER        optional; default to the A2VM_INTAKE_* ones
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import sys
from urllib.parse import urlsplit


def _list(value: str) -> list[str]:
    return [v.strip() for v in re.split(r"[,;\s]+", value or "") if v.strip()]


def egress_of(endpoints: list[str], explicit: str = "") -> list[dict]:
    if explicit:
        out = []
        for item in _list(explicit):
            cidr, _, port = item.rpartition(":")
            ipaddress.ip_network(cidr, strict=False)
            out.append({"cidr": cidr, "port": int(port)})
        return out
    out, seen = [], set()
    for url in endpoints:
        u = urlsplit(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError(f"{url}: not an http(s) URL")
        port = u.port or (443 if u.scheme == "https" else 80)
        try:
            addresses = [str(ipaddress.ip_address(u.hostname))]
        except ValueError:
            addresses = sorted({ai[4][0] for ai in socket.getaddrinfo(u.hostname, port, proto=socket.IPPROTO_TCP)})
        for a in addresses:
            cidr = f"{a}/{32 if ':' not in a else 128}"
            if (cidr, port) not in seen:
                seen.add((cidr, port))
                out.append({"cidr": cidr, "port": port})
    return out


def values(env: dict[str, str]) -> dict:
    endpoints = [u.rstrip("/") for u in _list(env.get("A2VM_LLM_BASE_URL", ""))]
    model = env.get("A2VM_LLM_MODEL", "")
    if not endpoints or not model:
        raise ValueError("the chat needs the tenant's LLM: A2VM_LLM_BASE_URL and A2VM_LLM_MODEL")
    ingress = {
        "controller": env.get("A2VM_CHAT_INGRESS_CONTROLLER") or env.get("A2VM_INTAKE_INGRESS_CONTROLLER") or "nginx",
        "className": env.get("A2VM_CHAT_INGRESS_CLASS") or env.get("A2VM_INTAKE_INGRESS_CLASS") or "",
        "tlsSecret": env.get("A2VM_CHAT_TLS_SECRET", ""),
        "clusterIssuer": env.get("A2VM_CHAT_CLUSTER_ISSUER") or env.get("A2VM_INTAKE_CLUSTER_ISSUER") or "",
        "allowFrom": _list(env.get("A2VM_CHAT_ALLOW", "")),
    }
    for cidr in ingress["allowFrom"]:
        ipaddress.ip_network(cidr, strict=False)
    chat = {
        "enabled": True,
        "host": env["A2VM_CHAT_HOST"],
        "llm": {
            "endpoints": endpoints,
            "model": model,
            "egress": egress_of(endpoints, env.get("A2VM_CHAT_LLM_EGRESS", "")),
        },
        "ingress": ingress,
    }
    if env.get("A2VM_CHAT_ADMIN_EMAIL"):
        chat["adminEmail"] = env["A2VM_CHAT_ADMIN_EMAIL"]
    if env.get("A2VM_CHAT_RETENTION_DAYS", "").strip():
        days = int(env["A2VM_CHAT_RETENTION_DAYS"])
        if days < 0:
            raise ValueError("A2VM_CHAT_RETENTION_DAYS: 0 (keep) or a number of days")
        chat["retentionDays"] = days
    return {"chat": chat}


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: chat_values.py OUT.json", file=sys.stderr)
        return 2
    try:
        v = values(dict(os.environ))
    except (ValueError, KeyError, OSError) as exc:
        print(f"chat: {exc}", file=sys.stderr)
        return 1
    with open(argv[0], "w", encoding="utf-8") as f:
        json.dump(v, f, indent=1)
    c = v["chat"]
    egress = ", ".join(f"{e['cidr']}:{e['port']}" for e in c["llm"]["egress"])
    print(
        f"chat: https://{c['host']}, model {c['llm']['model']} on {len(c['llm']['endpoints'])} endpoint(s), "
        f"egress {egress}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
