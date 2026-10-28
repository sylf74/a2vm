#!/bin/bash
# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
# Install an A2VM collector on a VM near a network (docs/collectors.md §2): configuration, image,
# one systemd service and timer per connector. It can be run again: each step only does what is
# missing. No secret is printed or passed as a command argument.
#
#   sudo bash install-collector.sh --tenant lab --collector lab-lan \
#     --service https://detect-lab.apps.example.org \
#     --image registry.example.org/vulnops/a2vm/detect:v0.15.1 \
#     [--openvas-hosts "192.0.2.0/24, 198.51.100.0/24" --gvm-socket-volume <docker volume of gvmd.sock>] \
#     [--gvm-user a2vm-scan] [--schedule "*-*-* 07:30:00"]
#
# Files read from the current folder when the step needs them (removed once installed):
#   scan_key               private key of the read-only scan account (SSH targets)
#   targets.yaml           the targets file of the tenant project (client = --tenant)
#   registry-user.txt, registry-password.txt   a deploy token with read_registry, to pull the image
# Already in place (made by hand, docs/collectors.md §2):
#   /etc/a2vm/collector/token    the collector's token, also in A2VM_COLLECTOR_TOKEN_<ID>
#   /etc/a2vm/collector/ca.pem   CA of the push endpoint's certificate
#   /etc/docker/certs.d/<registry>/ca.crt   CA of the registry, when private
#
# With --openvas-hosts, the collector drives gvmd on this host through its socket (Greenbone
# Community Edition with Docker Compose): it makes the GMP account --gvm-user in gvmd when
# /etc/a2vm/collector/gvm.env is missing, and gives the network scan a connector of its own.

set -eu

usage() { sed -n '3,14p' "$0" | sed 's/^# \{0,1\}//'; }

TENANT="" COLLECTOR="" SERVICE="" IMAGE="" OPENVAS_HOSTS="" SOCKET_VOLUME=""
GVM_USER="a2vm-scan" SCHEDULE="*-*-* 07:30:00"
while [ $# -gt 0 ]; do
  case "$1" in
    --tenant) TENANT=$2; shift 2 ;;
    --collector) COLLECTOR=$2; shift 2 ;;
    --service) SERVICE=$2; shift 2 ;;
    --image) IMAGE=$2; shift 2 ;;
    --openvas-hosts) OPENVAS_HOSTS=$2; shift 2 ;;
    --gvm-socket-volume) SOCKET_VOLUME=$2; shift 2 ;;
    --gvm-user) GVM_USER=$2; shift 2 ;;
    --schedule) SCHEDULE=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
ID_RE='^[a-z0-9][a-z0-9-]{0,62}$'
for pair in "tenant:$TENANT" "collector:$COLLECTOR"; do
  if ! printf '%s' "${pair#*:}" | grep -Eq "$ID_RE"; then
    echo "--${pair%%:*} is required: lower-case letters, digits and dashes" >&2; exit 2
  fi
done
case "$SERVICE" in https://*) ;; *) echo "--service is required: the https URL of the push endpoint" >&2; exit 2 ;; esac
if [ -z "$IMAGE" ]; then echo "--image is required: <registry>/<path>/detect:<release tag>" >&2; exit 2; fi
if [ -n "$OPENVAS_HOSTS" ] && [ -z "$SOCKET_VOLUME" ]; then
  echo "--openvas-hosts needs --gvm-socket-volume (docker volume ls | grep gvmd)" >&2; exit 2
fi
if [ "$(id -u)" -ne 0 ]; then echo "run it with sudo" >&2; exit 1; fi

C=/etc/a2vm/collector
HERE=$(pwd)
REGISTRY=${IMAGE%%/*}
step() { echo "== $*"; }
fail() { echo "$*" >&2; exit 1; }

step "folders"
install -d -m 0750 -o 10001 -g 10001 "$C" "$C/ssh" /var/lib/a2vm /var/lib/a2vm-ssh
for f in "$C/token" "$C/ca.pem"; do [ -s "$f" ] || fail "missing $f (docs/collectors.md §2)"; done
grep -q 'BEGIN CERTIFICATE' "$C/ca.pem" || fail "$C/ca.pem is not a certificate"

step "targets.yaml"
if [ ! -s "$C/targets.yaml" ]; then
  [ -s "$HERE/targets.yaml" ] || fail "missing $HERE/targets.yaml (the targets file of the tenant project)"
  install -m 0640 -o 10001 -g 10001 "$HERE/targets.yaml" "$C/targets.yaml"
fi
grep -Eq "^client: *['\"]?$TENANT['\"]? *$" "$C/targets.yaml" || fail "$C/targets.yaml: 'client: $TENANT' expected"
SSH_TARGETS=0
if grep -q '^targets:' "$C/targets.yaml"; then SSH_TARGETS=1; fi

if [ "$SSH_TARGETS" -eq 1 ]; then
  step "scan key"
  if [ ! -s "$C/ssh/scan_key" ]; then
    [ -s "$HERE/scan_key" ] || fail "missing $HERE/scan_key (private key of the scan account)"
    tr -d '\r' < "$HERE/scan_key" | sed -e '$a\' > "$C/ssh/scan_key"
    chown 10001:10001 "$C/ssh/scan_key"; chmod 0600 "$C/ssh/scan_key"
    rm -f "$HERE/scan_key"
  fi
  ssh-keygen -y -f "$C/ssh/scan_key" > /dev/null || fail "$C/ssh/scan_key is not a usable private key"
  echo "key: $(ssh-keygen -l -f "$C/ssh/scan_key")"
  grep -q 'identity_file:' "$C/targets.yaml" || fail "$C/targets.yaml: add 'identity_file:' under ssh:"
  sed -i "s#identity_file: .*#identity_file: $C/ssh/scan_key#" "$C/targets.yaml"
fi

if [ -n "$OPENVAS_HOSTS" ]; then
  step "openvas section"
  if grep -q '^openvas:' "$C/targets.yaml"; then
    sed -i "/^openvas:/,/^[^ #]/ s#^\(  gmp:\).*#\1 unix:///run/gvmd/gvmd.sock#" "$C/targets.yaml"
  else
    printf '\nopenvas:\n  gmp: unix:///run/gvmd/gvmd.sock\n  hosts: [%s]\n  min_qod: 70\n  timeout_minutes: 240\n  reuse_hours: 6\n' \
      "$OPENVAS_HOSTS" >> "$C/targets.yaml"
  fi
  [ "$(grep -c '^openvas:' "$C/targets.yaml")" -eq 1 ] || fail "$C/targets.yaml: one openvas section expected"
  grep -A6 '^openvas:' "$C/targets.yaml"

  step "GMP account and gvm.env"
  if [ ! -s "$C/gvm.env" ]; then
    GVMD=$(docker ps --format '{{.Names}}' | grep -E '(^|[-_])gvmd([-_][0-9]+)?$' | head -1 || true)
    [ -n "$GVMD" ] || fail "no gvmd container (docker ps)"
    if docker exec -u gvmd "$GVMD" gvmd --get-users 2>/dev/null | grep -qx "$GVM_USER"; then
      fail "the account $GVM_USER exists but $C/gvm.env is missing: write it by hand (root, 0600), or set a new password with docker exec -u gvmd $GVMD gvmd --user=$GVM_USER --new-password=…"
    fi
    out=$(docker exec -u gvmd "$GVMD" gvmd --create-user="$GVM_USER" 2>&1)
    pw=$(printf '%s\n' "$out" | sed -n "s/.*password '\(.*\)'.*/\1/p")
    [ -n "$pw" ] || fail "creation of $GVM_USER: unexpected answer of gvmd"
    ( umask 077; printf 'A2VM_GVM_USER=%s\nA2VM_GVM_PASSWORD=%s\n' "$GVM_USER" "$pw" > "$C/gvm.env" )
    chown root:root "$C/gvm.env"; chmod 0600 "$C/gvm.env"
    unset pw out
    echo "account $GVM_USER made, its password in $C/gvm.env (root only)"
  else
    echo "$C/gvm.env present"
  fi
fi

step "collector.yaml"
{
  printf 'collector: %s\ntenant: %s\nservice: %s\ntoken_file: %s/token\nca_file: %s/ca.pem\n' \
    "$COLLECTOR" "$TENANT" "$SERVICE" "$C" "$C"
  printf 'work: /var/lib/a2vm/work\nspool: /var/lib/a2vm/spool\nconnectors:\n'
  if [ "$SSH_TARGETS" -eq 1 ]; then
    printf '  - {name: lan-ssh, type: targets, targets: %s/targets.yaml, ssh: true, openvas: false}\n' "$C"
  fi
  if [ -n "$OPENVAS_HOSTS" ]; then
    printf '  - {name: lan-openvas, type: targets, targets: %s/targets.yaml, ssh: false, openvas: true}\n' "$C"
  fi
} > "$C/collector.yaml"
chown 10001:10001 "$C/collector.yaml"; chmod 0640 "$C/collector.yaml"
CONNECTORS=$(sed -n 's/^  - {name: \([a-z-]*\),.*/\1/p' "$C/collector.yaml")
[ -n "$CONNECTORS" ] || fail "no connector: the targets file has neither targets nor --openvas-hosts"

step "image $IMAGE"
if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
  if [ -s "$HERE/registry-user.txt" ] && [ -s "$HERE/registry-password.txt" ]; then
    docker login "$REGISTRY" -u "$(cat "$HERE/registry-user.txt")" --password-stdin < "$HERE/registry-password.txt"
  fi
  docker pull -q "$IMAGE"
fi
rm -f "$HERE/registry-password.txt"

GROUP_ADD="" ENV_FILE="" SOCKET_MOUNT=""
if [ -n "$OPENVAS_HOSTS" ]; then
  step "gvmd socket"
  perm=$(docker run --rm -v "$SOCKET_VOLUME:/run/gvmd" --entrypoint stat "$IMAGE" -c '%a %g' /run/gvmd/gvmd.sock)
  echo "gvmd.sock: mode ${perm% *}, group ${perm#* }"
  case "${perm% *}" in *6|*7) ;; *) GROUP_ADD="--group-add ${perm#* } " ;; esac
  ENV_FILE="  --env-file $C/gvm.env \\"
  SOCKET_MOUNT="  -v $SOCKET_VOLUME:/run/gvmd \\"
fi

step "configuration read by the agent"
docker run --rm --user 10001:10001 -v "$C:$C:ro" --entrypoint python3 "$IMAGE" -c "
from detect.agent import load_config
from detect.collect import load_targets
cfg = load_config('$C/collector.yaml')
tf = load_targets('$C/targets.yaml')
cfg.token()
print('agent:', cfg.collector, cfg.tenant, [c.name for c in cfg.connectors])
print('SSH targets:', len(tf.targets), '; openvas:', tf.openvas.gmp if tf.openvas else 'none')
"

step "systemd units"
{
  cat <<EOF
[Unit]
Description=A2VM collector, connector %i
Wants=network-online.target docker.service
After=network-online.target docker.service

[Service]
Type=oneshot
SuccessExitStatus=3
TimeoutStartSec=6h
ExecStart=/usr/bin/docker run --rm --name a2vm-collector-%i --user 10001:10001 ${GROUP_ADD}\\
EOF
  [ -z "$ENV_FILE" ] || printf '%s\n' "$ENV_FILE"
  printf '  -v %s:%s:ro \\\n  -v /var/lib/a2vm:/var/lib/a2vm \\\n  -v /var/lib/a2vm-ssh:/home/a2vm/.ssh \\\n' "$C" "$C"
  [ -z "$SOCKET_MOUNT" ] || printf '%s\n' "$SOCKET_MOUNT"
  printf '  %s \\\n  detect agent run --config %s/collector.yaml --connector %%i\n' "$IMAGE" "$C"
} > /etc/systemd/system/a2vm-collector@.service
cat > /etc/systemd/system/a2vm-collector@.timer <<EOF
[Unit]
Description=A2VM collector, connector %i, daily

[Timer]
OnCalendar=$SCHEDULE
RandomizedDelaySec=10m
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
for c in $CONNECTORS; do systemctl enable --now "a2vm-collector@$c.timer"; done
systemctl list-timers 'a2vm-collector@*' --no-pager

echo
echo "installed. First runs:"
for c in $CONNECTORS; do
  echo "  sudo systemctl start --no-block a2vm-collector@$c.service; journalctl -u a2vm-collector@$c.service -f"
done
