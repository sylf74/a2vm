#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""A development identity provider for a tenant without one (v0.23.15, docs/dev-idp.md).

A platform for development may get no client from the company's identity provider. With
NGVM_DEV_IDP_HOST, deploy-k8s runs a Keycloak in the namespace with a realm made here: the tenant's
client (its redirect URIs, PKCE, the groups claim), the three groups of NGVM and local accounts,
each with a temporary password to change at the first sign-in. The sign-in then uses it as it
would the company's (NGVM_OIDC_* are derived from it). Never for production: a banner says DEV on
its sign-in page, deploy-k8s warns at each deployment. Without NGVM_DEV_IDP_HOST: nothing.

    NGVM_DEV_IDP_HOST           host of the Keycloak, e.g. idp-dev.apps.example.org
    NGVM_DEV_IDP_USERS          accounts: `e-mail:group,...`, group readers | validators | admins
    NGVM_DEV_IDP_STORAGE_CLASS  optional: storage class of its volume (else the cluster's default)
    NGVM_CHAT_HOST, NGVM_ALERTS_HOST, NGVM_DISPATCH_HOST   the addresses its client accepts
    NGVM_CHAT_INGRESS_*, NGVM_CHAT_CLUSTER_ISSUER, NGVM_CHAT_TLS_SECRET   its ingress, as the chat's

Usage: dev_idp_values.py <tenant> <values.json> <oidc.env>
Writes the chart's values (devIdp) and the NGVM_OIDC_* variables to export (no secret in either: the
passwords and the client's secret are keys of the Secret ngvm-tenant, read by Keycloak as ${...}).
"""

from __future__ import annotations

import json
import re
import sys

REALM = "ngvm-dev"
GROUPS = {"readers": "ngvm-readers", "validators": "ngvm-validators", "admins": "ngvm-admins"}
# An admin of the chat also uses it and validates; a validator also reads.
MEMBERSHIP = {
    "readers": ["ngvm-readers"],
    "validators": ["ngvm-validators"],
    "admins": ["ngvm-validators", "ngvm-admins"],
}
EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
HOST = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
MAX_USERS = 20


def users_of(value: str) -> list[dict]:
    """`e-mail:group,...` as accounts, in the order given (the index names their password)."""
    out, seen = [], set()
    for item in (value or "").replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        email, _, group = item.rpartition(":")
        email, group = email.strip().lower(), group.strip().lower()
        if not EMAIL.match(email):
            raise ValueError(f"NGVM_DEV_IDP_USERS: {item!r}: e-mail:group expected")
        if group not in GROUPS:
            raise ValueError(f"NGVM_DEV_IDP_USERS: {email}: group {group!r}, readers, validators or admins")
        if email in seen:
            raise ValueError(f"NGVM_DEV_IDP_USERS: {email} twice")
        seen.add(email)
        out.append({"email": email, "group": group})
    if not out:
        raise ValueError("NGVM_DEV_IDP_USERS: at least one account, e.g. ana@example.org:admins")
    if len(out) > MAX_USERS:
        raise ValueError(f"NGVM_DEV_IDP_USERS: {MAX_USERS} accounts at most (a development provider)")
    return out


def realm(tenant: str, users: list[dict], hosts: dict[str, str]) -> dict:
    """The realm Keycloak imports at its first start (`${...}`: from its environment, the Secret)."""
    redirects = []
    if hosts.get("chat"):
        redirects.append(f"https://{hosts['chat']}/oauth/oidc/callback")
    for key in ("alerts", "dispatch"):
        if hosts.get(key):
            redirects.append(f"https://{hosts[key]}/oauth2/callback")
    origins = [f"https://{h}" for h in hosts.values() if h]
    client = {
        "clientId": f"ngvm-{tenant}",
        "name": f"NGVM {tenant} (development)",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "clientAuthenticatorType": "client-secret",
        "secret": "${NGVM_DEV_IDP_CLIENT_SECRET}",
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "redirectUris": redirects,
        "webOrigins": origins,
        "attributes": {
            "pkce.code.challenge.method": "S256",
            "post.logout.redirect.uris": f"https://{hosts['chat']}/*" if hosts.get("chat") else "",
        },
        "protocolMappers": [
            {
                "name": "groups",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-group-membership-mapper",
                "consentRequired": False,
                "config": {
                    "full.path": "false",
                    "claim.name": "groups",
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "userinfo.token.claim": "true",
                },
            }
        ],
    }
    accounts = [
        {
            "username": u["email"],
            "email": u["email"],
            "emailVerified": True,  # oauth2-proxy refuses an unverified e-mail
            "enabled": True,
            "firstName": u["email"].split("@")[0],
            "lastName": "(dev)",
            "groups": [f"/{g}" for g in MEMBERSHIP[u["group"]]],
            "credentials": [{"type": "password", "value": "${NGVM_DEV_IDP_PW_" + str(i) + "}", "temporary": True}],
            "requiredActions": ["UPDATE_PASSWORD"],
        }
        for i, u in enumerate(users)
    ]
    return {
        "realm": REALM,
        "enabled": True,
        "displayName": "NGVM — DEVELOPMENT",
        "displayNameHtml": "<strong>NGVM — DEVELOPMENT identity provider</strong><br>not for production",
        "loginWithEmailAllowed": True,
        "duplicateEmailsAllowed": False,
        "registrationAllowed": False,
        "resetPasswordAllowed": False,
        "rememberMe": False,
        "bruteForceProtected": True,
        "passwordPolicy": "length(12)",
        "groups": [{"name": g} for g in GROUPS.values()],
        "clients": [client],
        "users": accounts,
    }


def values(tenant: str, env: dict[str, str]) -> tuple[dict, dict[str, str]]:
    host = env.get("NGVM_DEV_IDP_HOST", "").strip().lower()
    if not HOST.match(host):
        raise ValueError("NGVM_DEV_IDP_HOST: a host name, e.g. idp-dev.apps.example.org")
    names = (("chat", "NGVM_CHAT_HOST"), ("alerts", "NGVM_ALERTS_HOST"), ("dispatch", "NGVM_DISPATCH_HOST"))
    hosts = {k: env.get(v, "").strip().lower() for k, v in names}
    if not any(hosts.values()):
        raise ValueError("NGVM_DEV_IDP_HOST: no NGVM_CHAT_HOST, NGVM_ALERTS_HOST nor NGVM_DISPATCH_HOST to sign in to")
    users = users_of(env.get("NGVM_DEV_IDP_USERS", ""))
    ingress = {
        "controller": env.get("NGVM_CHAT_INGRESS_CONTROLLER") or env.get("NGVM_INTAKE_INGRESS_CONTROLLER") or "nginx",
        "className": env.get("NGVM_CHAT_INGRESS_CLASS") or env.get("NGVM_INTAKE_INGRESS_CLASS") or "",
        "clusterIssuer": env.get("NGVM_CHAT_CLUSTER_ISSUER") or env.get("NGVM_INTAKE_CLUSTER_ISSUER") or "",
        "tlsSecret": env.get("NGVM_DEV_IDP_TLS_SECRET", ""),
    }
    dev = {
        "enabled": True,
        "host": host,
        "users": len(users),
        "ingress": ingress,
        "realm": realm(tenant, users, hosts),
    }
    if env.get("NGVM_DEV_IDP_STORAGE_CLASS", "").strip():
        dev["storage"] = {"storageClass": env["NGVM_DEV_IDP_STORAGE_CLASS"].strip()}
    oidc = {
        "NGVM_OIDC_ISSUER": f"https://{host}/realms/{REALM}",
        "NGVM_OIDC_CLIENT_ID": f"ngvm-{tenant}",
        "NGVM_OIDC_READERS": GROUPS["readers"],
        "NGVM_OIDC_VALIDATORS": GROUPS["validators"],
        "NGVM_OIDC_ADMINS": GROUPS["admins"],
        "NGVM_OIDC_IN_CLUSTER": "true",
        "NGVM_OIDC_PROVIDER_NAME": "NGVM DEV",
    }
    return {"devIdp": dev}, oidc


def main(argv: list[str]) -> int:
    import os

    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    tenant = argv[1]
    try:
        out, oidc = values(tenant, dict(os.environ))
    except ValueError as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    with open(argv[2], "w", encoding="utf-8") as f:
        json.dump(out, f)
    with open(argv[3], "w", encoding="utf-8") as f:
        for k, v in oidc.items():
            f.write(f"export {k}='{v}'\n")
    for i, u in enumerate(users_of(os.environ.get("NGVM_DEV_IDP_USERS", ""))):
        print(f"dev identity provider: dev-idp-password-{i} {u['email']} ({u['group']})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
