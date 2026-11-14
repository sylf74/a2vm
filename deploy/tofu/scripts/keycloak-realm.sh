# shellcheck shell=bash
# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# The realm of the platform in a Keycloak that NGVM runs (sourced by keycloak-vm.sh and
# keycloak-k8s.sh, which define kc_exec). Settings:
#   REALM      the realm (ngvm)
#   CLIENTS    id|redirect-uri[,redirect-uri];... confidential OIDC clients (the portal, a chat)
#   KC_GROUPS  group;group... made when missing (who reads the dashboards, who uses the chat)
# Each client's secret, made by Keycloak, is written to /etc/ngvm/keycloak/clients/<id>.secret
# (root only) on the machine that runs this, where OpenTofu reads it.

# kc ARGS...: kcadm.sh in the Keycloak container (kc_exec), the admin's password read from
# ADMIN_PASSWORD_FILE on stdin into KC_CLI_PASSWORD, never on a command line.
kc() { kc_exec "$@" < "$ADMIN_PASSWORD_FILE"; }

kc_login() {
  local user=$1
  for _ in $(seq 60); do
    if kc config credentials --server http://localhost:8080 --realm master --user "$user" > /dev/null 2>&1; then
      return 0
    fi
    sleep 10
  done
  fail "kcadm: no sign-in to Keycloak after 10 minutes"
}

# shellcheck disable=SC2153 # CLIENTS: a setting of the step
kc_realm() {
  local out=/etc/ngvm/keycloak/clients scope g e id uris json cid secret
  if [ -n "$ROOT" ]; then printf 'RUN realm %s clients %s groups %s\n' "$REALM" "$CLIENTS" "${KC_GROUPS:-}" >> "$ROOT/commands.log"; return 0; fi
  kc_login "$ADMIN_USER"
  kc get "realms/$REALM" > /dev/null 2>&1 || kc create realms -s "realm=$REALM" -s enabled=true > /dev/null
  log "realm $REALM"

  scope=$(kc get client-scopes -r "$REALM" --fields id,name --format csv --noquotes | awk -F, '$2=="groups"{print $1}')
  if [ -z "$scope" ]; then
    scope=$(kc create client-scopes -r "$REALM" -s name=groups -s protocol=openid-connect \
      -s 'attributes."include.in.token.scope"=true' -i)
    kc create "client-scopes/$scope/protocol-mappers/models" -r "$REALM" -s name=groups -s protocol=openid-connect \
      -s protocolMapper=oidc-group-membership-mapper -s 'config."full.path"=false' -s 'config."claim.name"=groups' \
      -s 'config."id.token.claim"=true' -s 'config."access.token.claim"=true' -s 'config."userinfo.token.claim"=true' > /dev/null
  fi

  IFS=';' read -ra groups <<< "${KC_GROUPS:-}"
  for g in "${groups[@]}"; do
    [ -n "$g" ] || continue
    if ! kc get groups -r "$REALM" --fields name --format csv --noquotes | grep -qxF "$g"; then
      kc create groups -r "$REALM" -s "name=$g" > /dev/null
      log "group $g"
    fi
  done

  install -d -m 0700 "$out"
  IFS=';' read -ra clients <<< "$CLIENTS"
  for e in "${clients[@]}"; do
    [ -n "$e" ] || continue
    id=${e%%|*} uris=${e#*|}
    json=$(printf '%s' "$uris" | awk -F, '{for (i = 1; i <= NF; i++) printf "%s\"%s\"", (i > 1 ? "," : ""), $i}')
    cid=$(kc get clients -r "$REALM" -q "clientId=$id" --fields id --format csv --noquotes)
    if [ -z "$cid" ]; then
      cid=$(kc create clients -r "$REALM" -s "clientId=$id" -s enabled=true -s publicClient=false \
        -s standardFlowEnabled=true -s directAccessGrantsEnabled=false -s "redirectUris=[$json]" -i)
      log "client $id"
    else
      kc update "clients/$cid" -r "$REALM" -s "redirectUris=[$json]"
    fi
    kc update "clients/$cid/default-client-scopes/$scope" -r "$REALM" > /dev/null
    secret=$(kc get "clients/$cid/client-secret" -r "$REALM" --fields value --format csv --noquotes)
    [ -n "$secret" ] || fail "client $id: no secret"
    ( umask 077; printf '%s' "$secret" > "$out/$id.secret" )
    unset secret
  done
}
