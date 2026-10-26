# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""v0.13.1: the push endpoint behind Traefik (Middleware ipAllowList) and a certificate from
cert-manager; the deploy job hands both settings to the chart (docs/collectors.md)."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy" / "charts" / "a2vm-tenant"


def _intake() -> str:
    return (CHART / "templates" / "intake.yaml").read_text()


def test_values_offer_the_controllers_and_keep_nginx_by_default():
    ingress = yaml.safe_load((CHART / "values.yaml").read_text())["intake"]["ingress"]
    assert ingress["controller"] == "nginx"  # a tenant of v0.13.0 keeps its ingress unchanged
    assert ingress["clusterIssuer"] == "" and ingress["allowFrom"] == []
    assert "nginx" not in ingress  # replaced by controller; still read for v0.13.0 values (helpers)
    helpers = (CHART / "templates" / "_helpers.tpl").read_text()
    assert 'define "a2vm-tenant.ingressController"' in helpers
    assert '(eq (toString .Values.intake.ingress.nginx) "false")' in helpers
    assert "must be nginx, traefik or other" in helpers
    assert '(ne $controller "other") (not .Values.intake.ingress.allowFrom)' in helpers


def test_traefik_gets_an_allow_list_middleware_attached_to_the_ingress():
    text = _intake()
    traefik = text.split('{{- if eq $controller "traefik" }}', 1)[1].split("{{- end }}", 1)[0]
    for needle in ("apiVersion: traefik.io/v1alpha1", "kind: Middleware", "ipAllowList:", "sourceRange:"):
        assert needle in traefik, needle
    assert "{{- range $ing.allowFrom }}" in traefik
    assert (
        'traefik.ingress.kubernetes.io/router.middlewares: {{ printf "%s-%s-detect-allow@kubernetescrd" '
        ".Release.Namespace $name | quote }}" in text
    )
    assert "nginx.ingress.kubernetes.io/whitelist-source-range" in text  # nginx unchanged


def test_cert_manager_issues_the_certificate_when_asked():
    text = _intake()
    assert "cert-manager.io/cluster-issuer: {{ $ing.clusterIssuer | quote }}" in text
    assert "secretName: {{ $tls | quote }}" in text
    helpers = (CHART / "templates" / "_helpers.tpl").read_text()
    assert '{{- printf "%s-detect-tls" (include "a2vm-tenant.name" .) -}}' in helpers


def test_deploy_job_hands_controller_and_issuer_to_the_chart():
    script = "\n".join(yaml.safe_load((ROOT / "templates" / "client-pipeline.yml").read_text())["deploy-k8s"]["script"])
    for variable, key in (
        ("A2VM_INTAKE_INGRESS_CONTROLLER", "controller"),
        ("A2VM_INTAKE_CLUSTER_ISSUER", "clusterIssuer"),
        ("A2VM_INTAKE_TLS_SECRET", "tlsSecret"),
    ):
        assert f'if [ -n "${{{variable}:-}}" ]; then printf \'    {key}: "%s"\\n\' "${variable}"' in script
    guide = (ROOT / "docs" / "collectors.md").read_text()
    for needle in (
        "A2VM_INTAKE_INGRESS_CONTROLLER",
        "A2VM_INTAKE_CLUSTER_ISSUER",
        "externalTrafficPolicy: Local",
        "--env-file",
        "unix:///run/gvmd/gvmd.sock",
        "End-to-end check",
    ):
        assert needle in guide, needle
