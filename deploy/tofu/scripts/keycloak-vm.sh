#!/bin/bash
# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# Keycloak on a VM of its own, with Podman (docs/platform.md §7): PostgreSQL, Keycloak and Caddy in
# front of it for HTTPS, then the realm of the platform and its clients. Called by OpenTofu as
# `keycloak-vm.sh <work dir>`, with keycloak.env:
#   PUBLIC_HOST          public name of Keycloak (auth.example.org)
#   TLS                 files (stage tls.crt and tls.key), acme (Let's Encrypt, the name reachable
#                       from the internet) or internal (Caddy's own CA, for a lab)
#   ACME_EMAIL
#   KEYCLOAK_IMAGE, POSTGRES_IMAGE, CADDY_IMAGE
#   REALM, CLIENTS, KC_GROUPS as keycloak-realm.sh
#   HTTP_PROXY_URL, HTTPS_PROXY_URL, NO_PROXY_LIST
# The passwords of the database and of the bootstrap admin are made here once, in
# /etc/ngvm/keycloak (root only), and never leave the machine.

set -euo pipefail
WORK=${1:?usage: keycloak-vm.sh <work dir>}
# shellcheck source=lib.sh
. "$WORK/scripts/lib.sh"
# shellcheck source=keycloak-realm.sh
. "$WORK/scripts/keycloak-realm.sh"
load_env "$WORK/keycloak.env"
[ -n "$ROOT" ] || [ "$(id -u)" -eq 0 ] || fail "run as root"
K=/etc/ngvm/keycloak

log "system"
proxy_env
packages_proxy
trust_cas
install_packages podman
registry_cas

log "secrets in $K"
install -d -m 0700 "$ROOT$K" "$ROOT$K/caddy"
secret_once() {  # FILE: a random password, made once
  [ -s "$ROOT$1" ] || ( umask 077; head -c 32 /dev/urandom | base64 | tr -d '/+=\n' > "$ROOT$1" )
}
secret_once "$K/db-password"
secret_once "$K/admin-password"
ADMIN_USER="admin"
ADMIN_PASSWORD_FILE=$ROOT$K/admin-password
{ printf 'POSTGRES_PASSWORD=%s\nKC_DB_PASSWORD=%s\n' "$(cat "$ROOT$K/db-password")" "$(cat "$ROOT$K/db-password")"; } \
  | put 0600 "$K/db.env" || true
{ printf 'KC_BOOTSTRAP_ADMIN_USERNAME=%s\nKC_BOOTSTRAP_ADMIN_PASSWORD=%s\n' "$ADMIN_USER" "$(cat "$ADMIN_PASSWORD_FILE")"; } \
  | put 0600 "$K/admin.env" || true

case "$TLS" in
  files)
    staged tls.crt "$K/caddy/tls.crt" 0644 || true
    staged tls.key "$K/caddy/tls.key" 0600 || true
    if [ ! -s "$ROOT$K/caddy/tls.crt" ] || [ ! -s "$ROOT$K/caddy/tls.key" ]; then fail "TLS=files: stage tls.crt and tls.key"; fi
    tls_line="tls /etc/caddy/tls.crt /etc/caddy/tls.key" ;;
  internal) tls_line="tls internal" ;;
  acme) tls_line="tls ${ACME_EMAIL:?TLS=acme needs ACME_EMAIL}" ;;
  *) fail "TLS: files, acme or internal" ;;
esac
CHANGED=1
put 0644 "$K/caddy/Caddyfile" <<EOF && CHANGED=0
# Written by NGVM (deploy/tofu).
$PUBLIC_HOST {
	$tls_line
	reverse_proxy 127.0.0.1:8080
}
EOF

log "images"
if [ -z "$ROOT" ]; then
  for i in "$POSTGRES_IMAGE" "$KEYCLOAK_IMAGE" "$CADDY_IMAGE"; do podman pull -q "$i" > /dev/null; done
fi

log "systemd units"
# svc NAME DESCRIPTION AFTER PODMAN-ARGS...: a service that runs one container, restarted on failure.
svc() {
  local name=$1 desc=$2 after=$3
  shift 3
  cat <<EOF
# Written by NGVM (deploy/tofu): changes are lost at the next apply.
[Unit]
Description=$desc
Wants=network-online.target $after
After=network-online.target $after

[Service]
Restart=always
RestartSec=10
TimeoutStartSec=10min
ExecStart=/usr/bin/podman run --rm --replace --pull=never --name $name --network host --security-opt label=disable $*
ExecStop=/usr/bin/podman stop -t 30 $name

[Install]
WantedBy=multi-user.target
EOF
}
svc ngvm-keycloak-db "NGVM Keycloak, its PostgreSQL" "" \
  --env-file $K/db.env -e POSTGRES_USER=keycloak -e POSTGRES_DB=keycloak \
  -v ngvm-keycloak-db:/var/lib/postgresql/data "$POSTGRES_IMAGE" -c listen_addresses=127.0.0.1 \
  | put 0644 /etc/systemd/system/ngvm-keycloak-db.service && CHANGED=0
svc ngvm-keycloak "NGVM Keycloak" ngvm-keycloak-db.service \
  --env-file $K/db.env --env-file $K/admin.env -e KC_DB=postgres \
  -e KC_DB_URL=jdbc:postgresql://127.0.0.1:5432/keycloak -e KC_DB_USERNAME=keycloak \
  -e KC_HOSTNAME="https://$PUBLIC_HOST" -e KC_HTTP_ENABLED=true -e KC_HTTP_HOST=127.0.0.1 \
  -e KC_PROXY_HEADERS=xforwarded "$KEYCLOAK_IMAGE" start \
  | put 0644 /etc/systemd/system/ngvm-keycloak.service && CHANGED=0
svc ngvm-keycloak-proxy "NGVM Keycloak, HTTPS in front of it" ngvm-keycloak.service \
  -v $K/caddy/Caddyfile:/etc/caddy/Caddyfile:ro -v $K/caddy/tls.crt:/etc/caddy/tls.crt:ro \
  -v $K/caddy/tls.key:/etc/caddy/tls.key:ro -v ngvm-keycloak-caddy:/data "$CADDY_IMAGE" \
  | put 0644 /etc/systemd/system/ngvm-keycloak-proxy.service && CHANGED=0
if [ "$TLS" != files ]; then
  # no certificate files: the mounts of tls.crt and tls.key would fail
  [ -n "$ROOT" ] || { touch "$K/caddy/tls.crt" "$K/caddy/tls.key"; chmod 0600 "$K/caddy/tls.key"; }
fi

[ "$CHANGED" -ne 0 ] || run systemctl daemon-reload
for u in ngvm-keycloak-db ngvm-keycloak ngvm-keycloak-proxy; do
  run systemctl enable "$u"
  if [ -z "$ROOT" ]; then
    if ! systemctl is-active --quiet "$u"; then systemctl start "$u"; elif [ "$CHANGED" -eq 0 ]; then systemctl restart "$u"; fi
  fi
done

kc_exec() {
  podman exec -i ngvm-keycloak sh -c 'IFS= read -r KC_CLI_PASSWORD; export KC_CLI_PASSWORD; exec /opt/keycloak/bin/kcadm.sh "$@"' sh "$@"
}
kc_realm
log "Keycloak https://$PUBLIC_HOST, realm $REALM"
