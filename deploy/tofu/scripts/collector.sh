#!/bin/bash
# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# A collector near a network, with Podman (docs/platform.md §6, docs/collectors.md): its files,
# its image, one systemd service and timer per connector and the poll. Called by OpenTofu as
# `collector.sh <work dir>`, with collector.env:
#   TENANT, COLLECTOR     as in the collector's collector.yaml
#   IMAGE                 <registry>/<path>/detect:<release tag>
#   CONNECTORS            name=OnCalendar;... (e.g. lan-ssh=*-*-* 07:30:00)
#   CONTAINER_PROXY       true: the proxy of the platform given to the container; false: none
#                         (a transparent proxy, or an API reached directly)
#   OPENVAS_SOCKET_DIR    host folder that holds gvmd.sock (Greenbone on this host), or empty
#   LEGACY_CLEANUP        true: the units of an A2VM collector (before v0.25.0) stopped and removed
#   HTTP_PROXY_URL, HTTPS_PROXY_URL, NO_PROXY_LIST
# and in stage/: collector.yaml, the files it names (token, ca.pem, targets.yaml, keys…),
# installed in /etc/ngvm/collector under the same names; gvm.env (root only, given to the
# container as its environment); registry-user, registry-password; ca-<n>.pem; registry-<r>.pem.

set -euo pipefail
WORK=${1:?usage: collector.sh <work dir>}
# shellcheck source=lib.sh
. "$WORK/scripts/lib.sh"
load_env "$WORK/collector.env"
[ -n "$ROOT" ] || [ "$(id -u)" -eq 0 ] || fail "run as root"
ID_RE='^[a-z0-9][a-z0-9-]{0,62}$'
for v in "$TENANT" "$COLLECTOR"; do [[ "$v" =~ $ID_RE ]] || fail "not an id: $v"; done
[ -s "$WORK/stage/collector.yaml" ] || fail "stage collector.yaml"
C=/etc/ngvm/collector
AUTH=/etc/ngvm/registry-auth.json
REGISTRY=${IMAGE%%/*}

log "system"
proxy_env
packages_proxy
trust_cas
install_packages podman
registry_cas

if [ "${LEGACY_CLEANUP:-false}" = true ] && [ -z "$ROOT" ]; then
  for u in $(systemctl list-unit-files 'a2vm-collector*' --no-legend 2>/dev/null | awk '{print $1}'); do
    log "A2VM unit $u removed"
    systemctl disable --now "$u" 2>/dev/null || true
  done
  rm -f /etc/systemd/system/a2vm-collector@.service /etc/systemd/system/a2vm-collector@.timer \
    /etc/systemd/system/a2vm-collector-poll.service /etc/systemd/system/a2vm-collector-poll.timer
  systemctl daemon-reload
fi

log "files of $COLLECTOR in $C"
install -d -m 0750 "$ROOT$C" "$ROOT/var/lib/ngvm" "$ROOT/var/lib/ngvm-ssh"
[ -n "$ROOT" ] || chown 10001:10001 "$C" /var/lib/ngvm /var/lib/ngvm-ssh
for f in "$WORK"/stage/*; do
  [ -e "$f" ] || continue
  n=$(basename "$f")
  case "$n" in
    registry-*|ca-*.pem) ;;
    gvm.env) staged gvm.env "$C/gvm.env" 0600 root:root || true ;;
    *) staged "$n" "$C/$n" 0600 10001:10001 || true ;;
  esac
done
grep -Eq "^collector: *['\"]?${COLLECTOR}['\"]? *\$" "$ROOT$C/collector.yaml" || fail "collector.yaml: 'collector: $COLLECTOR' expected"
grep -Eq "^tenant: *['\"]?${TENANT}['\"]? *\$" "$ROOT$C/collector.yaml" || fail "collector.yaml: 'tenant: $TENANT' expected"

log "image $IMAGE"
podman_login "$REGISTRY" "$AUTH"
if [ -z "$ROOT" ]; then
  auth=()
  [ -s "$AUTH" ] && auth=(--authfile "$AUTH")
  podman pull -q "${auth[@]}" "$IMAGE" > /dev/null
fi

extra=""
if [ -n "${OPENVAS_SOCKET_DIR:-}" ]; then
  [ -n "$ROOT" ] || [ -S "$OPENVAS_SOCKET_DIR/gvmd.sock" ] || fail "no gvmd.sock in $OPENVAS_SOCKET_DIR"
  extra="  -v $OPENVAS_SOCKET_DIR:/run/gvmd \\"
  if [ -z "$ROOT" ]; then
    perm=$(stat -c '%a %g' "$OPENVAS_SOCKET_DIR/gvmd.sock")
    case "${perm% *}" in *6|*7) ;; *) extra="$extra
  --group-add ${perm#* } \\" ;; esac
  fi
fi
[ -s "$ROOT$C/gvm.env" ] && extra="$extra${extra:+
}  --env-file $C/gvm.env \\"

proxy_lines="" http_proxy_flag=false
if [ "${CONTAINER_PROXY:-false}" = true ] && [ -n "${HTTP_PROXY_URL:-}" ]; then
  http_proxy_flag=true
  proxy_lines="Environment=HTTP_PROXY=$HTTP_PROXY_URL HTTPS_PROXY=${HTTPS_PROXY_URL:-$HTTP_PROXY_URL} NO_PROXY=${NO_PROXY_LIST:-}"
fi

if [ -z "$ROOT" ]; then
  log "configuration read by the agent"
  podman run --rm --pull=never --http-proxy=false --security-opt label=disable --user 10001:10001 \
    -v "$C:$C:ro" --entrypoint python3 "$IMAGE" -c "
from detect.agent import load_config
cfg = load_config('$C/collector.yaml')
cfg.token()
print('agent:', cfg.collector, cfg.tenant, [c.name for c in cfg.connectors])
"
fi

log "systemd units"
CHANGED=1
# unit DESCRIPTION NAME COMMAND [PRE]: a oneshot service that runs the agent in the image.
unit() {
  cat <<EOF
# Written by NGVM (deploy/tofu): changes are lost at the next apply.
[Unit]
Description=$1
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
SuccessExitStatus=3
TimeoutStartSec=6h
EOF
  [ -z "$proxy_lines" ] || printf '%s\n' "$proxy_lines"
  [ -z "${4:-}" ] || printf 'ExecStartPre=%s\n' "$4"
  printf 'ExecStart=/usr/bin/podman run --rm --replace --pull=never --name %s --http-proxy=%s \\\n' "$2" "$http_proxy_flag"
  printf '  --security-opt label=disable --user 10001:10001 \\\n'
  printf '  -v %s:%s:ro \\\n  -v /var/lib/ngvm:/var/lib/ngvm \\\n  -v /var/lib/ngvm-ssh:/home/ngvm/.ssh \\\n' "$C" "$C"
  [ -z "$extra" ] || printf '%s\n' "$extra"
  [ -z "${4:-}" ] || printf '  -v /run/ngvm-collector:/run/ngvm-collector:ro \\\n'
  printf '  %s \\\n  %s\n' "$IMAGE" "$3"
}
unit "NGVM collector, connector %i" "ngvm-collector-%i" \
  "detect agent run --config $C/collector.yaml --connector %i" \
  | put 0644 /etc/systemd/system/ngvm-collector@.service && CHANGED=0
unit "NGVM collector, poll" "ngvm-collector-poll" \
  "detect agent poll --config $C/collector.yaml --timers /run/ngvm-collector/timers.json" \
  "/bin/sh -c 'mkdir -p /run/ngvm-collector && systemctl list-timers \"ngvm-collector@*\" --all -o json > /run/ngvm-collector/timers.json'" \
  | put 0644 /etc/systemd/system/ngvm-collector-poll.service && CHANGED=0
put 0644 /etc/systemd/system/ngvm-collector-poll.timer <<'EOF' && CHANGED=0
[Unit]
Description=NGVM collector, poll every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF
put 0644 /etc/systemd/system/ngvm-collector@.timer <<'EOF' && CHANGED=0
[Unit]
Description=NGVM collector, connector %i

[Timer]
RandomizedDelaySec=10m
Persistent=true

[Install]
WantedBy=timers.target
EOF

names=()
IFS=';' read -ra entries <<< "$CONNECTORS"
for e in "${entries[@]}"; do
  [ -n "$e" ] || continue
  name=${e%%=*} when=${e#*=}
  [[ "$name" =~ $ID_RE ]] || fail "connector: not an id: $name"
  grep -Eq "name: *['\"]?${name}['\"]?([ ,}]|$)" "$ROOT$C/collector.yaml" || fail "collector.yaml has no connector $name"
  printf '[Timer]\nOnCalendar=%s\n' "$when" | put 0644 "/etc/systemd/system/ngvm-collector@$name.timer.d/schedule.conf" && CHANGED=0
  names+=("$name")
done
[ ${#names[@]} -gt 0 ] || fail "CONNECTORS: at least one connector and its schedule"

# Timers of connectors no longer listed: stopped and removed.
for d in "$ROOT"/etc/systemd/system/ngvm-collector@*.timer.d; do
  [ -e "$d" ] || continue
  n=${d##*/ngvm-collector@}; n=${n%.timer.d}
  if [[ " ${names[*]} " != *" $n "* ]]; then
    log "connector $n no longer listed: its timer removed"
    run systemctl disable --now "ngvm-collector@$n.timer"
    rm -rf "$d"
    CHANGED=0
  fi
done

[ "$CHANGED" -ne 0 ] || run systemctl daemon-reload
for n in "${names[@]}"; do run systemctl enable --now "ngvm-collector@$n.timer"; done
run systemctl enable --now ngvm-collector-poll.timer
if [ -z "$ROOT" ]; then
  systemctl restart ngvm-collector-poll.timer
  systemctl list-timers 'ngvm-collector@*' --no-pager
fi
log "collector $COLLECTOR ready: systemctl start --no-block ngvm-collector@${names[0]}.service"
