# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.17.0: the analysts sign in with the tenant's identity provider; the review page of the alerts
on via serve (behind oauth2-proxy), the validated alerts mailed by the sender."""

from __future__ import annotations

import json
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest
import yaml

from via.service.review import Denied, Review, make_handler

from .conftest import ROOT
from .test_alert import PROFILE
from .test_v0160 import READ, RUN, TENANT, _service, _watch, forget_alert, service  # noqa: F401 - fixture

CHART = ROOT / "deploy" / "charts" / "a2vm-tenant"
CONTACTS = """schema_version: 1
contacts:
  - {name: IT, email: it@example.org}
  - {name: RSSI, role: RSSI, email: rssi@example.org, language: fr}
"""
URL = "https://alerts-lab.apps.example.org"
KEY = b"k" * 32


class _NoRedirect(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):
        return response

    https_response = http_response


OPENER = urllib.request.build_opener(_NoRedirect)


def _alerts(svc, url, token):
    assert _watch(url, token) == 0
    forget_alert(svc)
    assert _watch(url, token) == 0
    return svc.store.alerts(TENANT)


@pytest.fixture
def page(service, monkeypatch, tmp_path):  # noqa: F811 - the fixture of test_v0160
    svc, url, token = service
    monkeypatch.delenv("A2VM_ANALYST_TO", raising=False)
    alerts = _alerts(svc, url, token)
    contacts = tmp_path / "contacts.yaml"
    contacts.write_text(CONTACTS)
    review = Review(
        TENANT, svc.store, KEY, {"A2VM-Readers"}, {"A2VM-Validators"}, URL, contacts=contacts, profile=PROFILE
    )
    from a2vm.service import serve as plain_serve

    httpd = plain_serve(make_handler(review), "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield review, f"http://127.0.0.1:{httpd.server_address[1]}", alerts, svc, url, token
    httpd.shutdown()
    httpd.server_close()


def _call(base, path, user="ana@example.org", groups="A2VM-Readers", form=None, origin=URL):
    headers = {"X-Forwarded-Email": user, "X-Forwarded-Groups": groups} if user else {}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        if origin:
            headers["Origin"] = origin
    req = urllib.request.Request(base + path, data=data, headers=headers, method="POST" if data else "GET")
    with OPENER.open(req, timeout=10) as r:
        return r.status, r.read().decode(), dict(r.headers)


def test_who_may_read_and_who_may_act(page):
    review, base, alerts, *_ = page
    a = alerts[0]
    q = urllib.parse.quote(a["id"], safe="")
    assert _call(base, "/", user="")[0] == 401
    assert _call(base, "/", groups="Other")[0] == 403
    status, body, headers = _call(base, "/")
    assert status == 200 and a["title"] in __import__("html").unescape(body)
    assert (
        "script-src" not in headers["Content-Security-Policy"]
        and "default-src 'none'" in headers["Content-Security-Policy"]
    )
    status, body, _ = _call(base, f"/alerts/{q}")
    assert status == 200 and "Read only" in body and "Validate" not in body
    assert _call(base, f"/alerts/{q}/edit")[0] == 403
    assert _call(base, f"/alerts/{q}/validate", form={"token": review.token("ana@example.org", a["id"])})[0] == 403
    # A Keycloak full group path names the same group.
    status, body, _ = _call(base, f"/alerts/{q}", user="val@example.org", groups="/A2VM-Validators")
    assert status == 200 and "Choose these recipients and translate" in body and "rssi@example.org" in body


def test_forms_need_their_token_and_the_page_origin(page):
    review, base, alerts, svc, *_ = page
    a = alerts[0]
    q = urllib.parse.quote(a["id"], safe="")
    val = {"user": "val@example.org", "groups": "A2VM-Validators"}
    good = {"token": review.token("val@example.org", a["id"])}
    assert _call(base, f"/alerts/{q}/validate", form={"token": "0" * 64}, **val)[0] == 403
    assert _call(base, f"/alerts/{q}/validate", form=good, origin="https://evil.example", **val)[0] == 403
    other = {"token": review.token("someone@example.org", a["id"])}  # another analyst's token
    assert _call(base, f"/alerts/{q}/validate", form=other, **val)[0] == 403
    assert _call(base, f"/alerts/{q}/validate", form=good, **val)[0] == 409  # no recipient chosen yet
    assert _call(base, f"/alerts/{q}/prepare", form={**good, "to": "nobody@example.org"}, **val)[0] == 422
    assert _call(base, f"/alerts/{q}/prepare", form={**good, "to": "it@example.org"}, **val)[0] == 303
    assert svc.store.alert(TENANT, a["id"])["status"] == "translating"  # English only: ready at once
    status, _, headers = _call(base, f"/alerts/{q}/validate", form=good, **val)
    assert status == 303 and headers["Location"] == f"/alerts/{q}"
    assert svc.store.alert(TENANT, a["id"])["status"] == "validated"
    [e] = [e for e in svc.store.events(TENANT) if e["event"] == "validated"]
    assert e["by"] == "val@example.org" and e["alert"] == a["id"] and e["to"] == ["it@example.org"]
    assert _call(base, f"/alerts/{q}/validate", form=good, **val)[0] == 409  # already validated
    assert _call(base, f"/alerts/{q}/dismiss", form=good, **val)[0] == 303
    assert svc.store.alert(TENANT, a["id"])["status"] == "dismissed"


def test_a_validator_corrects_the_sheet_within_its_cves(page):
    review, base, alerts, svc, url, token = page
    a = alerts[0]
    q = urllib.parse.quote(a["id"], safe="")
    val = {"user": "val@example.org", "groups": "A2VM-Validators"}
    good = {"token": review.token("val@example.org", a["id"])}
    original = review.original(a)
    status, body, _ = _call(base, f"/alerts/{q}/edit", form={**good, "text": original + "\nCVE-2001-0001\n"}, **val)
    assert status == 422 and "CVE-2001-0001" in body
    assert svc.store.edit(TENANT, a["id"]) is None
    fixed = original.replace("## Description", "## Description\n\nAnalyst's note: fix published.", 1)
    assert _call(base, f"/alerts/{q}/edit", form={**good, "text": fixed}, **val)[0] == 303
    assert "Analyst's note" in svc.store.edit(TENANT, a["id"])
    assert svc.store.alert(TENANT, a["id"])["edited"] is True
    assert "Analyst's note" in svc.get_alert(TENANT, READ, a["id"])["sheet"]  # the chat reads the correction
    assert "Analyst's note" in svc.get_edit(TENANT, RUN, a["id"]).decode()


def test_the_sender_mails_the_validated_alerts_once_with_the_correction(page, tmp_path, monkeypatch):
    review, base, alerts, svc, url, token = page
    monkeypatch.delenv("A2VM_SMTP_HOST", raising=False)
    a = alerts[0]
    review.save_edit(review.alert(a["id"]), "val@example.org", review.original(a) + "\nAnalyst's note: seen.\n")
    review.prepare(review.alert(a["id"]), "val@example.org", ["it@example.org"])
    review.act(review.alert(a["id"]), "val@example.org", "validate")
    contacts = tmp_path / "contacts.yaml"
    assert _service(url, token, "send", PROFILE, "--contacts", str(contacts), "--validated") == 0
    after = svc.store.alert(TENANT, a["id"])
    assert after["status"] == "sent"
    sent = [e for e in svc.store.events(TENANT) if e["event"] == "sent"]
    assert [e["alert"] for e in sent] == [a["id"]] and sent[0]["to"] == ["it@example.org"]
    assert sent[0]["language"] == "en"
    assert _service(url, token, "send", PROFILE, "--contacts", str(contacts), "--validated") == 0
    assert len([e for e in svc.store.events(TENANT) if e["event"] == "sent"]) == 1  # nothing validated left
    others = [x for x in svc.store.alerts(TENANT) if x["id"] != a["id"]]
    assert all(x["status"] == "pending" for x in others)  # never sent without a validation


def test_review_refuses_a_weak_configuration():
    with pytest.raises(ValueError):
        Review(TENANT, None, b"short", set(), {"V"}, URL)
    with pytest.raises(ValueError):
        Review(TENANT, None, KEY, {"R"}, set(), URL)
    with pytest.raises(ValueError):
        Review(TENANT, None, KEY, set(), {"V"}, "http://alerts.example.org")
    r = Review(TENANT, None, KEY, set(), {"V"}, URL)
    with pytest.raises(Denied):
        r.who({"X-Forwarded-Email": "x@example.org", "X-Forwarded-Groups": "R2"})


def test_the_analysts_mail_links_to_the_review_page(monkeypatch):
    from via.alert.cli import _send_link

    monkeypatch.setenv("A2VM_SEND_PIPELINE_URL", "https://gitlab.example.org/x/-/pipelines/new")
    monkeypatch.setenv("A2VM_REVIEW_URL", URL)
    link = _send_link("lab-CERTFR-2026-ALE-001")
    assert f'href="{URL}/alerts/lab-CERTFR-2026-ALE-001"' in link and "pipelines" not in link


def _render(tmp_path, extra: dict) -> list[dict]:
    import shutil
    import subprocess

    mh = shutil.which("mh") or "/var/tmp/minihelm/mh"
    if not Path(mh).exists():
        pytest.skip("no chart renderer here (the CI lints the chart with helm)")
    base = {
        "tenant": "lab",
        "image": {"registry": "registry.example.org/vulnops/a2vm"},
        "secret": {"name": "a2vm-tenant"},
        "verdict": {"enabled": True, "digestsSecret": "a2vm-verdict"},
        "chat": {
            "enabled": True,
            "host": "chat-lab.apps.example.org",
            "toolsDigestsSecret": "a2vm-chat",
            "llm": {
                "endpoints": ["http://192.0.2.10:8000/v1"],
                "model": "m",
                "egress": [{"cidr": "192.0.2.10/32", "port": 8000}],
            },
        },
        "watch": {"enabled": True, "digestsSecret": "a2vm-via"},
    }
    for k, v in extra.items():
        base[k] = {**base.get(k, {}), **v} if isinstance(v, dict) else v
    values = tmp_path / "values.yaml"
    values.write_text(yaml.safe_dump(base))
    out = subprocess.run(
        [mh, str(CHART), "-f", str(values), "--set-file", f"files.profile={ROOT / 'examples' / 'lab' / 'client.yaml'}"],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert out.returncode == 0, out.stderr
    return [d for d in yaml.safe_load_all(out.stdout) if d]


OIDC = {
    "issuerUrl": "https://auth.example.org/realms/a2vm",
    "clientId": "a2vm-lab",
    "readers": ["A2VM-Readers"],
    "validators": ["A2VM-Validators"],
    "egress": [{"cidr": "192.0.2.20", "port": 443}],
}


def test_chart_signs_the_analysts_in_and_keeps_the_page_behind_the_proxy(tmp_path):
    docs = _render(
        tmp_path, {"oidc": OIDC, "watch": {"review": {"enabled": True, "host": "alerts-lab.apps.example.org"}}}
    )
    by = {(d["kind"], d["metadata"]["name"]): d for d in docs}
    proxy = by[("Deployment", "a2vm-lab-review")]["spec"]["template"]["spec"]["containers"][0]["args"]
    assert "--allowed-group=A2VM-Readers" in proxy and "--allowed-group=A2VM-Validators" in proxy
    assert "--upstream=http://a2vm-lab-via:8081/" in proxy and "--code-challenge-method=S256" in proxy
    assert not any("secret=" in a for a in proxy)  # secrets from files only
    np = by[("NetworkPolicy", "a2vm-lab-via")]["spec"]["ingress"]
    page = [r for r in np if r["ports"] == [{"port": 8081, "protocol": "TCP"}]]
    assert (
        len(page) == 1 and page[0]["from"][0]["podSelector"]["matchLabels"]["app.kubernetes.io/component"] == "review"
    )
    chat = by[("Deployment", "a2vm-lab-chat")]["spec"]["template"]["spec"]["containers"][0]
    env = {e["name"]: e.get("value") for e in chat["env"]}
    assert (
        env["OAUTH_ALLOWED_ROLES"] == "A2VM-Readers,A2VM-Validators" and env["OAUTH_MERGE_ACCOUNTS_BY_EMAIL"] == "false"
    )
    assert env["ENABLE_LOGIN_FORM"] == "true" and "OAUTH_CLIENT_SECRET" not in env
    sender = by[("Deployment", "a2vm-lab-sender")]["spec"]["template"]["spec"]
    assert sender["restartPolicy"] == "Always" and "--validated --every 30" in sender["containers"][0]["args"][0]
    watch = by[("CronJob", "a2vm-lab-watch")]["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]
    assert {"name": "A2VM_REVIEW_URL", "value": "https://alerts-lab.apps.example.org"} in watch["env"]


def test_chart_without_sign_in_stays_as_before(tmp_path):
    docs = _render(tmp_path, {})
    names = {d["metadata"]["name"] for d in docs}
    assert "a2vm-lab-review" not in names and "a2vm-lab-sender" not in names
    chat = next(d for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "a2vm-lab-chat")
    assert not any("OAUTH" in e["name"] for e in chat["spec"]["template"]["spec"]["containers"][0]["env"])


def test_sign_in_values_of_the_deploy_job(monkeypatch):
    import sys

    sys.path.insert(0, str(ROOT / "deploy" / "chat"))
    from sign_in_values import values

    env = {
        "A2VM_OIDC_ISSUER": "https://auth.example.org/realms/a2vm/",
        "A2VM_OIDC_CLIENT_ID": "a2vm-lab",
        "A2VM_OIDC_CLIENT_SECRET": "x",
        "A2VM_OIDC_READERS": "A2VM-Readers",
        "A2VM_OIDC_VALIDATORS": "A2VM-Validators",
        "A2VM_OIDC_EGRESS": "192.0.2.20/32:443",
        "A2VM_ALERTS_HOST": "alerts-lab.apps.example.org",
    }
    v = values(env, "kubernetes")
    assert v["oidc"]["issuerUrl"] == "https://auth.example.org/realms/a2vm"
    assert v["oidc"]["egress"] == [{"cidr": "192.0.2.20/32", "port": 443}] and v["oidc"]["ca"] is False
    assert v["watch"]["review"]["host"] == "alerts-lab.apps.example.org"
    with pytest.raises(ValueError, match="kubernetes"):
        values(env, "gitlab")
    with pytest.raises(ValueError, match="VALIDATORS"):
        values({**env, "A2VM_OIDC_VALIDATORS": ""}, "kubernetes")
    with pytest.raises(ValueError, match="CLIENT_SECRET"):
        values({**env, "A2VM_OIDC_CLIENT_SECRET": ""}, "kubernetes")
    with pytest.raises(ValueError):
        values({**env, "A2VM_OIDC_READERS": "a;b"}, "kubernetes")
    assert re.match(r"^https://", values(env, "kubernetes")["oidc"]["issuerUrl"])
    assert json.dumps(v)  # JSON for helm -f
