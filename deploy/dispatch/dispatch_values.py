#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""Values of the dispatch service for the chart, written by the job deploy-k8s (v0.20.0,
docs/dispatch.md). Standard library and PyYAML only.

Reads the tenant project's dispatch.yaml and variables, and writes a values file (JSON, which Helm
reads as YAML): where the targets of dispatch.yaml are, for the NetworkPolicy (their hosts resolved
here, in the job), and the page of the requests for remediation. Also writes the names of the
targets, one per line, so that the job copies each one's credential into the tenant's Secret.

    NGVM_DISPATCH_<TARGET>_PASSWORD   credential of a target (masked), <TARGET> its name in capitals,
                                      - as _ (read by the job, not here)
    NGVM_DISPATCH_<TARGET>_CA         optional, File: the CA of its certificate (idem)
    NGVM_DISPATCH_EGRESS              optional: `cidr:port,...` instead of resolving the targets
    NGVM_DISPATCH_IN_CLUSTER          optional: true when the targets are reached through the cluster's ingress
    NGVM_DISPATCH_HOST                host of the page of the requests for remediation (D18)
    NGVM_OIDC_REMEDIATORS             groups that may ask for remediation (with NGVM_DISPATCH_HOST)
    NGVM_DISPATCH_ALLOW               optional: the persons' networks (CIDR, comma-separated)
    NGVM_DISPATCH_TLS_SECRET          optional; ingress controller, class and issuer as the chat's

    dispatch_values.py dispatch.yaml OUT.json TARGETS.txt
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sys

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "chat"))
from chat_values import _list, egress_of  # noqa: E402 - the helpers of the chat's values
from sign_in_values import _groups  # noqa: E402

TARGET = re.compile(r"^[a-z][a-z0-9-]{0,30}$")


def env_name(target: str) -> str:
    return "NGVM_DISPATCH_" + target.upper().replace("-", "_")


def values(rules: dict, env: dict[str, str]) -> tuple[dict, list[str]]:
    targets = rules.get("targets") or {}
    names = sorted(targets)
    for name in names:
        if not TARGET.match(name):
            raise ValueError(f"target {name!r}: lowercase letters, digits and - only")
        if not env.get(f"{env_name(name)}_PASSWORD"):
            raise ValueError(f"target {name}: the variable {env_name(name)}_PASSWORD (masked) is missing")
    in_cluster = env.get("NGVM_DISPATCH_IN_CLUSTER", "").lower() == "true"
    urls = [str(t.get("url", "")) for t in targets.values()]
    dispatch: dict = {
        "enabled": True,
        "inCluster": in_cluster,
        "egress": []
        if in_cluster and not env.get("NGVM_DISPATCH_EGRESS")
        else egress_of(urls, env.get("NGVM_DISPATCH_EGRESS", ""))
        if urls
        else [],
    }
    host = env.get("NGVM_DISPATCH_HOST", "")
    if host:
        if not env.get("NGVM_OIDC_ISSUER"):
            raise ValueError("NGVM_DISPATCH_HOST needs NGVM_OIDC_ISSUER: the persons must sign in")
        remediators = _groups(env.get("NGVM_OIDC_REMEDIATORS", ""))
        if not remediators:
            raise ValueError("NGVM_DISPATCH_HOST needs NGVM_OIDC_REMEDIATORS: nobody could ask for remediation")
        ingress = {
            "controller": env.get("NGVM_CHAT_INGRESS_CONTROLLER")
            or env.get("NGVM_INTAKE_INGRESS_CONTROLLER")
            or "nginx",
            "className": env.get("NGVM_CHAT_INGRESS_CLASS") or env.get("NGVM_INTAKE_INGRESS_CLASS") or "",
            "tlsSecret": env.get("NGVM_DISPATCH_TLS_SECRET", ""),
            "clusterIssuer": env.get("NGVM_CHAT_CLUSTER_ISSUER") or env.get("NGVM_INTAKE_CLUSTER_ISSUER") or "",
            "allowFrom": _list(env.get("NGVM_DISPATCH_ALLOW", "")),
        }
        for cidr in ingress["allowFrom"]:
            ipaddress.ip_network(cidr, strict=False)
        dispatch["page"] = {"enabled": True, "host": host, "remediators": remediators, "ingress": ingress}
    return {"dispatch": dispatch}, names


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: dispatch_values.py dispatch.yaml OUT.json TARGETS.txt", file=sys.stderr)
        return 2
    try:
        with open(argv[0], encoding="utf-8") as f:
            rules = yaml.safe_load(f) or {}
        v, names = values(rules, dict(os.environ))
    except (ValueError, OSError, yaml.YAMLError) as exc:
        print(f"dispatch: {exc}", file=sys.stderr)
        return 1
    with open(argv[1], "w", encoding="utf-8") as f:
        json.dump(v, f, indent=1)
    with open(argv[2], "w", encoding="utf-8") as f:
        f.write("".join(f"{n}\n" for n in names))
    d = v["dispatch"]
    where = ", ".join(f"{e['cidr']}:{e['port']}" for e in d["egress"])
    where = where or ("the cluster's ingress" if d["inCluster"] else "none")
    print(f"dispatch: mode {rules.get('mode', 'dry-run')}, targets {', '.join(names) or 'none'} at {where}")
    if "page" in d:
        print(f"page of the requests: https://{d['page']['host']} for {', '.join(d['page']['remediators'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
