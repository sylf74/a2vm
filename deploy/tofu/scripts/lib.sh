# shellcheck shell=bash
# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# Functions shared by the scripts that OpenTofu runs on the machines (sourced, not run).
#
# Every script is called as `<script> <work dir>`: the work dir holds the scripts, the settings of
# the step (`<step>.env`, no secret) and `stage/`, the secret files OpenTofu uploaded for it. The
# script copies what it needs where it belongs and the caller removes the work dir. A script can
# be run again: each step only changes what differs.
#
# NGVM_TEST_ROOT (tests only): every path written is under this folder, and no command that
# changes the machine runs.

ROOT=${NGVM_TEST_ROOT:-}

log() { printf '== %s\n' "$*"; }
fail() { printf 'ERROR %s\n' "$*" >&2; exit 1; }

# run CMD...: a command that changes the machine; printed and skipped in tests.
run() {
  if [ -n "$ROOT" ]; then printf 'RUN %s\n' "$*" >> "$ROOT/commands.log"; return 0; fi
  "$@"
}

# load_env FILE: the settings of the step, KEY='value' lines written by OpenTofu.
load_env() {
  [ -f "$1" ] || fail "missing $1"
  set -a
  # shellcheck disable=SC1090
  . "$1"
  set +a
}

# put MODE DEST [OWNER]: stdin into DEST (under ROOT), only when it changed; 0 changed, 1 same.
put() {
  local mode=$1 dest=$ROOT$2 owner=${3:-root:root} tmp
  mkdir -p "$(dirname "$dest")"
  tmp=$(mktemp "$(dirname "$dest")/.ngvm.XXXXXX")
  cat > "$tmp"
  if [ -f "$dest" ] && cmp -s "$tmp" "$dest"; then rm -f "$tmp"; return 1; fi
  chmod "$mode" "$tmp"
  [ -n "$ROOT" ] || chown "$owner" "$tmp"
  mv -f "$tmp" "$dest"
  return 0
}

# staged NAME DEST MODE [OWNER]: a secret file OpenTofu uploaded, moved to DEST; 0 changed.
staged() {
  local src=$WORK/stage/$1
  [ -s "$src" ] || return 1
  put "$3" "$2" "${4:-root:root}" < "$src"
}

os_family() {
  # shellcheck disable=SC1091
  . "${ROOT}/etc/os-release"
  case " ${ID:-} ${ID_LIKE:-} " in
    *" ubuntu "*|*" debian "*) echo debian ;;
    *" rhel "*|*" rocky "*|*" fedora "*|*" centos "*) echo rhel ;;
    *) fail "unsupported system ${ID:-?}: Ubuntu or Rocky Linux expected" ;;
  esac
}

# proxy_env: the proxy of the platform for the commands of this script (empty: none).
proxy_env() {
  if [ -n "${HTTP_PROXY_URL:-}" ]; then
    export http_proxy=$HTTP_PROXY_URL HTTP_PROXY=$HTTP_PROXY_URL
    export https_proxy=${HTTPS_PROXY_URL:-$HTTP_PROXY_URL} HTTPS_PROXY=${HTTPS_PROXY_URL:-$HTTP_PROXY_URL}
    export no_proxy=$NO_PROXY_LIST NO_PROXY=$NO_PROXY_LIST
  fi
}

# trust_cas: the CA files staged as ca-<n>.pem into the system's trust store.
trust_cas() {
  local family changed=1 f n
  family=$(os_family)
  for f in "$WORK"/stage/ca-*.pem; do
    [ -e "$f" ] || continue
    n=$(basename "$f" .pem)
    if [ "$family" = debian ]; then
      staged "$n.pem" "/usr/local/share/ca-certificates/ngvm-$n.crt" 0644 && changed=0
    else
      staged "$n.pem" "/etc/pki/ca-trust/source/anchors/ngvm-$n.pem" 0644 && changed=0
    fi
  done
  if [ "$changed" -eq 0 ]; then
    if [ "$family" = debian ]; then run update-ca-certificates; else run update-ca-trust; fi
  fi
}

# packages_proxy: the package manager through the proxy.
packages_proxy() {
  [ -n "${HTTP_PROXY_URL:-}" ] || return 0
  if [ "$(os_family)" = debian ]; then
    printf 'Acquire::http::Proxy "%s";\nAcquire::https::Proxy "%s";\n' \
      "$HTTP_PROXY_URL" "${HTTPS_PROXY_URL:-$HTTP_PROXY_URL}" | put 0644 /etc/apt/apt.conf.d/95ngvm-proxy || true
  else
    if ! grep -qs "^proxy=$HTTP_PROXY_URL\$" "$ROOT/etc/dnf/dnf.conf"; then
      run sed -i '/^proxy=/d' /etc/dnf/dnf.conf
      run sed -i "/^\[main\]/a proxy=$HTTP_PROXY_URL" /etc/dnf/dnf.conf
    fi
  fi
}

# install_packages PKG...: those missing.
install_packages() {
  if [ "$(os_family)" = debian ]; then
    local missing=() p
    for p in "$@"; do dpkg -s "$p" > /dev/null 2>&1 || missing+=("$p"); done
    [ ${#missing[@]} -eq 0 ] && return 0
    run apt-get update -qq
    DEBIAN_FRONTEND=noninteractive run apt-get install -y -qq "${missing[@]}"
  else
    local missing=() p
    for p in "$@"; do rpm -q "$p" > /dev/null 2>&1 || missing+=("$p"); done
    [ ${#missing[@]} -eq 0 ] && return 0
    run dnf install -y -q "${missing[@]}"
  fi
}

# registry_cas DIR: the registry CA files staged as registry-<registry>.pem, for Podman.
registry_cas() {
  local f reg
  for f in "$WORK"/stage/registry-*.pem; do
    [ -e "$f" ] || continue
    reg=$(basename "$f" .pem); reg=${reg#registry-}
    staged "registry-$reg.pem" "/etc/containers/certs.d/$reg/ca.crt" 0644 || true
  done
}

# podman_login REGISTRY AUTHFILE: a login with the staged registry-user and registry-password.
podman_login() {
  local user pass
  [ -s "$WORK/stage/registry-user" ] && [ -s "$WORK/stage/registry-password" ] || return 0
  user=$(tr -d '\r\n' < "$WORK/stage/registry-user")
  pass=$(tr -d '\r\n' < "$WORK/stage/registry-password")
  install -d -m 0700 "$ROOT$(dirname "$2")"
  if [ -n "$ROOT" ]; then printf 'RUN podman login %s\n' "$1" >> "$ROOT/commands.log"; return 0; fi
  printf '%s' "$pass" | podman login --authfile "$2" -u "$user" --password-stdin "$1" > /dev/null
  chmod 0600 "$2"
}
