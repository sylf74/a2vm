#!/bin/bash
# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# A node of the RKE2 cluster (docs/platform.md §4): server or agent, behind the proxy and the
# registry mirrors of the platform. Called by OpenTofu as `rke2.sh <work dir>`, with rke2.env:
#   ROLE              server or agent
#   SERVER_URL        https://<first server>:9345, empty on the first server
#   NODE_NAME, NODE_IP
#   TLS_SAN           extra names of the API server, comma-separated (servers)
#   RKE2_VERSION      e.g. v1.33.5+rke2r1; empty: the latest of RKE2_CHANNEL
#   RKE2_CHANNEL      stable by default
#   INSTALL_URL       the RKE2 install script (https://get.rke2.io)
#   INGRESS           ingress-nginx or traefik (servers)
#   CIS               true: the CIS profile of RKE2
#   CLUSTER_CIDR, SERVICE_CIDR
#   DISABLE_FIREWALL  true: firewalld or ufw stopped, as RKE2 asks
#   MIRRORS           registry=endpoint[,endpoint];... (registries.yaml)
#   HTTP_PROXY_URL, HTTPS_PROXY_URL, NO_PROXY_LIST
# and in stage/: token (the cluster's secret), ca-<n>.pem, registry-<registry>.pem.

set -euo pipefail
WORK=${1:?usage: rke2.sh <work dir>}
# shellcheck source=lib.sh
. "$WORK/scripts/lib.sh"
load_env "$WORK/rke2.env"
case "$ROLE" in server|agent) ;; *) fail "ROLE: server or agent" ;; esac
[ "$ROLE" = server ] || [ -n "${SERVER_URL:-}" ] || fail "an agent needs SERVER_URL"
[ -n "$ROOT" ] || [ "$(id -u)" -eq 0 ] || fail "run as root"
FAMILY=$(os_family)
UNIT=rke2-$ROLE
CONF=/etc/rancher/rke2
RESTART=1

log "system ($FAMILY)"
proxy_env
packages_proxy
trust_cas
if [ "$FAMILY" = debian ]; then install_packages curl tar ca-certificates; else install_packages curl tar; fi

if [ "${DISABLE_FIREWALL:-true}" = true ]; then
  for fw in firewalld ufw; do
    if [ -z "$ROOT" ] && systemctl is-active --quiet "$fw" 2>/dev/null; then
      log "firewall $fw stopped (RKE2 manages the rules of the nodes)"
      run systemctl disable --now "$fw"
    fi
  done
fi

if [ "$FAMILY" = rhel ]; then
  cat <<'EOF' | put 0644 /etc/NetworkManager/conf.d/rke2-canal.conf && { [ -n "$ROOT" ] || run systemctl reload NetworkManager; }
[keyfile]
unmanaged-devices=interface-name:flannel*;interface-name:cali*;interface-name:tunl*;interface-name:vxlan.calico;interface-name:vxlan-v6.calico;interface-name:wireguard.cali;interface-name:wg-v6.cali
EOF
fi

log "configuration"
install -d -m 0700 "$ROOT$CONF"
staged token "$CONF/ngvm-token" 0600 && RESTART=0
[ -s "$ROOT$CONF/ngvm-token" ] || fail "no cluster token (stage/token)"
{
  echo "# Written by NGVM (deploy/tofu): changes are lost at the next apply."
  echo "token-file: $CONF/ngvm-token"
  [ -z "${SERVER_URL:-}" ] || echo "server: $SERVER_URL"
  echo "node-name: $NODE_NAME"
  echo "node-ip: $NODE_IP"
  [ "$FAMILY" = rhel ] && echo "selinux: true"
  [ "${CIS:-false}" = true ] && echo "profile: cis"
  if [ "$ROLE" = server ]; then
    echo "write-kubeconfig-mode: \"0600\""
    echo "cni: canal"
    echo "ingress-controller: ${INGRESS:-ingress-nginx}"
    echo "cluster-cidr: ${CLUSTER_CIDR:-10.42.0.0/16}"
    echo "service-cidr: ${SERVICE_CIDR:-10.43.0.0/16}"
    echo "tls-san:"
    echo "  - $NODE_IP"
    IFS=, read -ra sans <<< "${TLS_SAN:-}"
    for s in "${sans[@]}"; do [ -z "$s" ] || echo "  - $s"; done
  fi
  true
} | put 0600 "$CONF/config.yaml" && RESTART=0

{
  echo "# Written by NGVM (deploy/tofu)."
  IFS=';' read -ra entries <<< "${MIRRORS:-}"
  if [ ${#entries[@]} -gt 0 ]; then
    echo "mirrors:"
    for e in "${entries[@]}"; do
      [ -n "$e" ] || continue
      echo "  \"${e%%=*}\":"
      echo "    endpoint:"
      IFS=, read -ra eps <<< "${e#*=}"
      for ep in "${eps[@]}"; do echo "      - \"$ep\""; done
    done
  fi
  first=1
  for f in "$WORK"/stage/registry-*.pem; do
    [ -e "$f" ] || continue
    reg=$(basename "$f" .pem); reg=${reg#registry-}
    staged "registry-$reg.pem" "$CONF/registry-$reg.crt" 0644 || true
    [ "$first" -eq 0 ] || echo "configs:"
    first=0
    printf '  "%s":\n    tls:\n      ca_file: %s/registry-%s.crt\n' "$reg" "$CONF" "$reg"
  done
  true
} | put 0600 "$CONF/registries.yaml" && RESTART=0

no_proxy="127.0.0.1,localhost,${CLUSTER_CIDR:-10.42.0.0/16},${SERVICE_CIDR:-10.43.0.0/16},.svc,.cluster.local"
[ -z "${NO_PROXY_LIST:-}" ] || no_proxy="$no_proxy,$NO_PROXY_LIST"
if [ -n "${HTTP_PROXY_URL:-}" ]; then
  printf 'HTTP_PROXY=%s\nHTTPS_PROXY=%s\nNO_PROXY=%s\n' \
    "$HTTP_PROXY_URL" "${HTTPS_PROXY_URL:-$HTTP_PROXY_URL}" "$no_proxy" | put 0644 "/etc/default/$UNIT" && RESTART=0
else
  : | put 0644 "/etc/default/$UNIT" && RESTART=0
fi

log "RKE2 ${RKE2_VERSION:-${RKE2_CHANNEL:-stable}} ($ROLE)"
installed=""
if [ -z "$ROOT" ] && command -v rke2 > /dev/null 2>&1; then installed=$(rke2 --version | head -1); fi
if [ -z "$installed" ] || { [ -n "${RKE2_VERSION:-}" ] && [[ "$installed" != *"$RKE2_VERSION"* ]]; }; then
  if [ -n "$ROOT" ]; then
    printf 'RUN install rke2 %s %s\n' "$ROLE" "${RKE2_VERSION:-${RKE2_CHANNEL:-stable}}" >> "$ROOT/commands.log"
  else
    script=$(mktemp)
    curl -sfL "${INSTALL_URL:-https://get.rke2.io}" -o "$script"
    INSTALL_RKE2_TYPE=$ROLE INSTALL_RKE2_VERSION=${RKE2_VERSION:-} INSTALL_RKE2_CHANNEL=${RKE2_CHANNEL:-stable} sh "$script"
    rm -f "$script"
  fi
  RESTART=0
fi

if [ "${CIS:-false}" = true ]; then
  if [ "$ROLE" = server ] && ! getent passwd etcd > /dev/null 2>&1; then
    run useradd -r -c "etcd user" -s /sbin/nologin -M etcd -U
  fi
  for d in /usr/share/rke2 /usr/local/share/rke2 /opt/rke2/share/rke2; do
    if [ -f "$d/rke2-cis-sysctl.conf" ]; then
      put 0644 /etc/sysctl.d/60-rke2-cis.conf < "$d/rke2-cis-sysctl.conf" && run systemctl restart systemd-sysctl
      break
    fi
  done
fi

if [ "$ROLE" = server ]; then
  put 0644 /etc/profile.d/ngvm-rke2.sh <<EOF || true
export PATH="\$PATH:/var/lib/rancher/rke2/bin"
[ "\$(id -u)" -ne 0 ] || export KUBECONFIG=$CONF/rke2.yaml
EOF
fi

log "service $UNIT"
run systemctl enable "$UNIT"
if [ -n "$ROOT" ]; then
  exit 0
elif ! systemctl is-active --quiet "$UNIT"; then
  systemctl start "$UNIT"
elif [ "$RESTART" -eq 0 ]; then
  systemctl restart "$UNIT"
fi
systemctl is-active --quiet "$UNIT" || fail "$UNIT is not running: journalctl -u $UNIT"

if [ "$ROLE" = server ]; then
  export PATH="$PATH:/var/lib/rancher/rke2/bin" KUBECONFIG=$CONF/rke2.yaml
  for _ in $(seq 60); do
    if kubectl get node "$NODE_NAME" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null | grep -qx True; then
      log "node $NODE_NAME ready"
      exit 0
    fi
    sleep 10
  done
  fail "node $NODE_NAME not ready after 10 minutes: kubectl get nodes; journalctl -u $UNIT"
fi
log "agent $NODE_NAME started"
