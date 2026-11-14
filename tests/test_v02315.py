# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.23.15: a development identity provider, off unless asked.

A platform for development whose company gives NGVM no OIDC client gets a Keycloak in its namespace,
with a realm made for NGVM. The realm was imported into Keycloak 26.4 while writing this version:
the client's secret from the environment, PKCE, the groups claim, verified e-mails, temporary
passwords that ask for a change."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys

import pytest
import yaml

from .conftest import ROOT

CHART = ROOT / "deploy/charts/ngvm-tenant"
ENV = {
    "NGVM_DEV_IDP_HOST": "idp-dev.apps.example.org",
    "NGVM_DEV_IDP_USERS": "Ana@Example.org:admins, bob@example.org:validators;carl@example.org:readers",
    "NGVM_CHAT_HOST": "chat.example.org",
    "NGVM_ALERTS_HOST": "alerts.example.org",
    "NGVM_CHAT_CLUSTER_ISSUER": "company-ca",
    "NGVM_CHAT_INGRESS_CLASS": "nginx",
}


def _module():
    spec = importlib.util.spec_from_file_location("dev_idp_values", ROOT / "deploy/chat/dev_idp_values.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_realm_is_made_for_ngvm() -> None:
    out, oidc = _module().values("lab", ENV)
    dev = out["devIdp"]
    assert dev["enabled"] and dev["host"] == "idp-dev.apps.example.org" and dev["users"] == 3
    assert dev["ingress"]["clusterIssuer"] == "company-ca" and dev["ingress"]["className"] == "nginx"
    realm = dev["realm"]
    assert realm["realm"] == "ngvm-dev" and not realm["registrationAllowed"] and realm["bruteForceProtected"]
    assert "DEVELOPMENT" in realm["displayNameHtml"]
    client = realm["clients"][0]
    assert client["clientId"] == "ngvm-lab" and client["secret"] == "${NGVM_DEV_IDP_CLIENT_SECRET}"
    assert client["redirectUris"] == [
        "https://chat.example.org/oauth/oidc/callback",
        "https://alerts.example.org/oauth2/callback",
    ]
    assert client["attributes"]["pkce.code.challenge.method"] == "S256" and not client["directAccessGrantsEnabled"]
    mapper = client["protocolMappers"][0]
    assert mapper["protocolMapper"] == "oidc-group-membership-mapper" and mapper["config"]["full.path"] == "false"
    assert mapper["config"]["claim.name"] == "groups"
    users = {u["email"]: u for u in realm["users"]}
    assert users["ana@example.org"]["groups"] == ["/ngvm-validators", "/ngvm-admins"]
    assert users["carl@example.org"]["groups"] == ["/ngvm-readers"]
    assert all(u["emailVerified"] and u["credentials"][0]["temporary"] for u in users.values())
    assert users["bob@example.org"]["credentials"][0]["value"] == "${NGVM_DEV_IDP_PW_1}"  # the order given
    assert oidc == {
        "NGVM_OIDC_ISSUER": "https://idp-dev.apps.example.org/realms/ngvm-dev",
        "NGVM_OIDC_CLIENT_ID": "ngvm-lab",
        "NGVM_OIDC_READERS": "ngvm-readers",
        "NGVM_OIDC_VALIDATORS": "ngvm-validators",
        "NGVM_OIDC_ADMINS": "ngvm-admins",
        "NGVM_OIDC_IN_CLUSTER": "true",
        "NGVM_OIDC_PROVIDER_NAME": "NGVM DEV",
    }
    assert "storage" not in dev
    assert _module().values("lab", {**ENV, "NGVM_DEV_IDP_STORAGE_CLASS": "fast"})[0]["devIdp"]["storage"] == {
        "storageClass": "fast"
    }


def test_the_sign_in_takes_what_it_derives() -> None:
    spec = importlib.util.spec_from_file_location("sign_in_values", ROOT / "deploy/chat/sign_in_values.py")
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(ROOT / "deploy/chat"))
    spec.loader.exec_module(mod)
    _, oidc = _module().values("lab", ENV)
    out = mod.values({**ENV, **oidc, "NGVM_OIDC_CLIENT_SECRET": "s" * 32}, "kubernetes")
    assert out["oidc"]["inCluster"] and out["oidc"]["egress"] == [] and out["oidc"]["admins"] == ["ngvm-admins"]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"NGVM_DEV_IDP_HOST": "https://idp"}, "host name"),
        ({"NGVM_DEV_IDP_USERS": ""}, "at least one"),
        ({"NGVM_DEV_IDP_USERS": "ana@example.org:root"}, "readers, validators or admins"),
        ({"NGVM_DEV_IDP_USERS": "not-an-email:admins"}, "e-mail:group"),
        ({"NGVM_DEV_IDP_USERS": "a@example.org:admins,A@example.org:readers"}, "twice"),
        ({"NGVM_CHAT_HOST": "", "NGVM_ALERTS_HOST": ""}, "sign in to"),
    ],
)
def test_wrong_settings_stop_the_job(change, message) -> None:
    with pytest.raises(ValueError, match=message):
        _module().values("lab", {**ENV, **change})


def test_the_script_writes_the_values_and_the_variables(tmp_path) -> None:
    script = str(ROOT / "deploy/chat/dev_idp_values.py")
    args = [sys.executable, script, "lab", str(tmp_path / "v.json"), str(tmp_path / "o.env")]
    proc = subprocess.run(args, env={**ENV, "PATH": "/usr/bin:/bin"}, capture_output=True, text=True, check=True)
    assert "dev-idp-password-0 ana@example.org (admins)" in proc.stdout
    assert json.loads((tmp_path / "v.json").read_text())["devIdp"]["users"] == 3
    assert (
        "export NGVM_OIDC_ISSUER='https://idp-dev.apps.example.org/realms/ngvm-dev'" in (tmp_path / "o.env").read_text()
    )


def test_the_pipeline_makes_it_only_when_asked() -> None:
    pipeline = yaml.safe_load((ROOT / "templates/client-pipeline.yml").read_text())
    script = "\n".join(pipeline["deploy-k8s"]["script"])
    block = next(x for x in pipeline["deploy-k8s"]["script"] if 'DEVIDP=""' in x)
    assert 'elif [ -n "${NGVM_DEV_IDP_HOST:-}" ]; then' in block
    assert "WARN NGVM_DEV_IDP_HOST ignored: NGVM_OIDC_ISSUER names the identity provider" in block
    assert "never for production" in block
    assert script.index('DEVIDP=""') < script.index('SIGNIN=""')  # the sign-in uses what it exports
    assert "$WATCH $DEVIDP $SIGNIN" in script
    assert 'put dev-idp-admin-password "$(cat "$K/dev-idp-admin-password")"' in script


def test_the_chart_runs_keycloak_only_when_enabled() -> None:
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["devIdp"]["enabled"] is False and values["devIdp"]["image"].startswith("quay.io/keycloak/keycloak:")
    tpl = (CHART / "templates/dev-idp.yaml").read_text()
    assert tpl.splitlines()[7] == "{{- if .Values.devIdp.enabled }}"
    for line in ('args: ["start", "--import-realm"]', "- {name: KC_DB, value: dev-file}",
                 "key: dev-idp-admin-password", "key: dev-idp-client-secret",
                 '{{ printf "dev-idp-password-%d" $i }}', "- path: /realms/", "helm.sh/resource-policy: keep",
                 "httpGet: {path: /health/ready, port: management}"):  # fmt: skip
        assert line in tpl
    assert "/admin" not in tpl.split("rules:")[1]  # the admin console is not published


def test_docs() -> None:
    doc = (ROOT / "docs/dev-idp.md").read_text(encoding="utf-8")
    assert "**Never for production.**" in doc and "NGVM_DEV_IDP_USERS" in doc
    assert "docs/dev-idp.md" in (ROOT / "docs/sign-in.md").read_text(encoding="utf-8")


def test_release_recorded() -> None:
    assert "## v0.23.15 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (CHART / "Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(23\.(1[5-9]|[2-9]\d)|2[4-9]\.\d+)$", chart, re.M)
