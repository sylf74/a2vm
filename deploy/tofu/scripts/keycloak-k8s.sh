#!/bin/bash
# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# Keycloak in the cluster (docs/platform.md §7), from the first server: the Keycloak operator, a
# CloudNativePG cluster for its database, a Keycloak and its Ingress, then the realm of the
# platform and its clients. Called by OpenTofu as `keycloak-k8s.sh <work dir>`, with keycloak.env:
#   NAMESPACE           keycloak
#   PUBLIC_HOST          public name of Keycloak (auth.example.org)
#   OPERATOR_URL        base of the operator's manifests (keycloak-k8s-resources/<version>/kubernetes)
#   KEYCLOAK_IMAGE      empty: the operator's default
#   INGRESS_CLASS, CLUSTER_ISSUER (empty: the certificate of TLS_SECRET, or the controller's default)
#   TLS_SECRET, STORAGE_SIZE
#   REALM, CLIENTS, KC_GROUPS as keycloak-realm.sh
#   HTTP_PROXY_URL, HTTPS_PROXY_URL, NO_PROXY_LIST

set -euo pipefail
WORK=${1:?usage: keycloak-k8s.sh <work dir>}
# shellcheck source=lib.sh
. "$WORK/scripts/lib.sh"
# shellcheck source=keycloak-realm.sh
. "$WORK/scripts/keycloak-realm.sh"
load_env "$WORK/keycloak.env"
[ -n "$ROOT" ] || [ "$(id -u)" -eq 0 ] || fail "run as root"
proxy_env
export PATH="$PATH:/var/lib/rancher/rke2/bin:/usr/local/bin" KUBECONFIG=/etc/rancher/rke2/rke2.yaml
ns=$NAMESPACE
tls_secret=${TLS_SECRET:-}
[ -n "$tls_secret" ] || [ -z "${CLUSTER_ISSUER:-}" ] || tls_secret=ngvm-keycloak-tls

apply_stdin() {
  if [ -n "$ROOT" ]; then cat >> "$ROOT/manifests.yaml"; echo --- >> "$ROOT/manifests.yaml"; return 0; fi
  kubectl apply --server-side --force-conflicts -f - > /dev/null
}

log "Keycloak operator in $ns"
printf 'apiVersion: v1\nkind: Namespace\nmetadata:\n  name: %s\n' "$ns" | apply_stdin
run kubectl apply --server-side --force-conflicts -f "$OPERATOR_URL/keycloaks.k8s.keycloak.org-v1.yml"
run kubectl apply --server-side --force-conflicts -f "$OPERATOR_URL/keycloakrealmimports.k8s.keycloak.org-v1.yml"
run kubectl apply --server-side --force-conflicts -n "$ns" -f "$OPERATOR_URL/kubernetes.yml"
run kubectl -n "$ns" rollout status deployment keycloak-operator --timeout 10m

log "database (CloudNativePG)"
apply_stdin <<EOF
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: ngvm-keycloak-db
  namespace: $ns
spec:
  instances: 1
  storage:
    size: ${STORAGE_SIZE:-2Gi}
  bootstrap:
    initdb:
      database: keycloak
      owner: keycloak
EOF
if [ -z "$ROOT" ]; then
  kubectl -n "$ns" wait cluster/ngvm-keycloak-db --for=condition=Ready --timeout 15m
fi

log "Keycloak $PUBLIC_HOST"
{
  cat <<EOF
apiVersion: k8s.keycloak.org/v2alpha1
kind: Keycloak
metadata:
  name: ngvm-keycloak
  namespace: $ns
spec:
  instances: 1
EOF
  [ -z "${KEYCLOAK_IMAGE:-}" ] || echo "  image: $KEYCLOAK_IMAGE"
  cat <<EOF
  db:
    vendor: postgres
    host: ngvm-keycloak-db-rw
    database: keycloak
    usernameSecret: {name: ngvm-keycloak-db-app, key: username}
    passwordSecret: {name: ngvm-keycloak-db-app, key: password}
  http:
    httpEnabled: true
  hostname:
    hostname: https://$PUBLIC_HOST
  proxy:
    headers: xforwarded
  ingress:
    enabled: false
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ngvm-keycloak
  namespace: $ns
EOF
  if [ -n "${CLUSTER_ISSUER:-}" ]; then
    printf '  annotations:\n    cert-manager.io/cluster-issuer: %s\n' "$CLUSTER_ISSUER"
  fi
  cat <<EOF
spec:
  ingressClassName: ${INGRESS_CLASS:-nginx}
EOF
  if [ -n "$tls_secret" ]; then
    printf '  tls:\n    - hosts: [%s]\n      secretName: %s\n' "$PUBLIC_HOST" "$tls_secret"
  else
    printf '  tls:\n    - hosts: [%s]\n' "$PUBLIC_HOST"
  fi
  cat <<EOF
  rules:
    - host: $PUBLIC_HOST
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: ngvm-keycloak-service
                port:
                  number: 8080
EOF
} | apply_stdin
if [ -z "$ROOT" ]; then
  kubectl -n "$ns" wait keycloak/ngvm-keycloak --for=condition=Ready --timeout 20m
fi

ADMIN_PASSWORD_FILE=$WORK/admin-password
if [ -z "$ROOT" ]; then
  ADMIN_USER=$(kubectl -n "$ns" get secret ngvm-keycloak-initial-admin -o jsonpath='{.data.username}' | base64 -d)
  ( umask 077; kubectl -n "$ns" get secret ngvm-keycloak-initial-admin -o jsonpath='{.data.password}' | base64 -d > "$ADMIN_PASSWORD_FILE" )
else
  ADMIN_USER=temp-admin
fi
kc_exec() {
  kubectl -n "$ns" exec -i ngvm-keycloak-0 -- sh -c 'IFS= read -r KC_CLI_PASSWORD; export KC_CLI_PASSWORD; exec /opt/keycloak/bin/kcadm.sh "$@"' sh "$@"
}
kc_realm
rm -f "$ADMIN_PASSWORD_FILE"
log "Keycloak https://$PUBLIC_HOST, realm $REALM"
