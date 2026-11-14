#!/bin/bash
# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# The portal (chart ngvm-portal, docs/reporting.md) from the first server, with the chart of the
# release that OpenTofu uploaded in charts/. Called as `portal.sh <work dir>`, with portal.env:
#   NAMESPACE, RELEASE      ngvm-portal, portal
#   REGISTRY                registry of the images, for the pull secret
# and in stage/: portal-values.yaml (the operator's values), registry-user, registry-password,
# oidc-client-secret (the portal's client of the identity provider, when it signs in with it).

set -euo pipefail
WORK=${1:?usage: portal.sh <work dir>}
# shellcheck source=lib.sh
. "$WORK/scripts/lib.sh"
load_env "$WORK/portal.env"
[ -n "$ROOT" ] || [ "$(id -u)" -eq 0 ] || fail "run as root"
proxy_env
export PATH="$PATH:/var/lib/rancher/rke2/bin:/usr/local/bin" KUBECONFIG=/etc/rancher/rke2/rke2.yaml
[ -s "$WORK/stage/portal-values.yaml" ] || fail "stage portal-values.yaml (the values of the portal)"
[ -d "$WORK/charts/ngvm-portal" ] || fail "missing charts/ngvm-portal"

ns=$NAMESPACE
if [ -z "$ROOT" ]; then
  kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f - > /dev/null
fi

set_args=()
if [ -s "$WORK/stage/registry-user" ] && [ -s "$WORK/stage/registry-password" ]; then
  log "pull secret ngvm-registry"
  auth=$(printf '%s:%s' "$(tr -d '\r\n' < "$WORK/stage/registry-user")" "$(tr -d '\r\n' < "$WORK/stage/registry-password")" | base64 -w0)
  ( umask 077; printf '{"auths":{"%s":{"auth":"%s"}}}' "$REGISTRY" "$auth" > "$WORK/dockerconfig.json" )
  unset auth
  if [ -z "$ROOT" ]; then
    kubectl -n "$ns" create secret generic ngvm-registry --type=kubernetes.io/dockerconfigjson \
      --from-file=.dockerconfigjson="$WORK/dockerconfig.json" --dry-run=client -o yaml | kubectl apply -f - > /dev/null
  fi
  rm -f "$WORK/dockerconfig.json"
  set_args+=(--set image.pullSecret=ngvm-registry)
fi

if [ -s "$WORK/stage/oidc-client-secret" ]; then
  log "secret $RELEASE-portal-oidc"
  if [ -z "$ROOT" ]; then
    kubectl -n "$ns" create secret generic "$RELEASE-portal-oidc" \
      --from-file=oidc-client-secret="$WORK/stage/oidc-client-secret" --dry-run=client -o yaml | kubectl apply -f - > /dev/null
  fi
fi

log "portal $RELEASE in $ns"
run helm upgrade --install "$RELEASE" "$WORK/charts/ngvm-portal" -n "$ns" \
  -f "$WORK/stage/portal-values.yaml" "${set_args[@]}" --wait --timeout 20m
if [ -z "$ROOT" ]; then kubectl -n "$ns" get pods; fi
