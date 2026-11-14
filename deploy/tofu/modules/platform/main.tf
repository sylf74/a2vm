# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# Every step is a terraform_data that copies the scripts of deploy/tofu/scripts and the files of
# the step to the machine, runs the script as root, and removes them. A step runs again when its
# settings, its scripts or `revision` change; a script only changes what differs.

locals {
  scripts = "${path.module}/../../scripts"
  # what makes a step run again, besides its own settings
  scripts_hash = sha256(join("", [for f in sort(fileset(local.scripts, "*.sh")) : filesha256("${local.scripts}/${f}")]))
  secrets_dir  = pathexpand(var.secrets_dir)
  key          = var.ssh.private_key_file == "" ? null : file(pathexpand(var.ssh.private_key_file))

  servers = sort([for n, h in var.hosts : n if contains(h.roles, "server")])
  agents  = toset([for n, h in var.hosts : n if contains(h.roles, "agent")])
  first   = length(local.servers) > 0 ? local.servers[0] : ""

  # files every machine gets: the CAs, the registry CAs (stage name -> local path)
  common_stage = merge(
    { for i, f in var.network.ca_files : "ca-${i + 1}.pem" => f },
    { for r, f in var.network.registry_ca_files : "registry-${r}.pem" => f },
  )
  registry_stage = var.registry.user_file == "" ? {} : {
    "registry-user"     = var.registry.user_file
    "registry-password" = var.registry.password_file
  }

  proxy_env = {
    HTTP_PROXY_URL  = var.network.http_proxy
    HTTPS_PROXY_URL = var.network.https_proxy
    NO_PROXY_LIST   = join(",", var.network.no_proxy)
  }
  mirrors = join(";", [for r, eps in var.network.registry_mirrors : "${r}=${join(",", eps)}"])

  # the clients Keycloak makes, as keycloak-realm.sh reads them
  kc_clients = join(";", [for id, uris in var.keycloak.clients : "${id}|${join(",", uris)}"])
  kc_host    = one([for n, h in var.hosts : n if contains(h.roles, "keycloak")])
  # where the secret of the portal's client is, on the operator's machine
  portal_oidc_secret = (
    var.portal.oidc_client_secret_file != "" ? var.portal.oidc_client_secret_file :
    var.keycloak.mode != "none" && contains(keys(var.keycloak.clients), var.keycloak.portal_client) ?
    "${local.secrets_dir}/keycloak/${var.keycloak.portal_client}.secret" : ""
  )
}

# A step's settings are written as KEY='value' lines (env_lines below), its secret files staged
# in a folder of its own under secrets_dir (stage_cmd) and uploaded with the scripts.
locals {
  stage_root = "${local.secrets_dir}/stage"
}

check "keycloak_host" {
  assert {
    condition     = var.keycloak.mode != "vm" || local.kc_host != null
    error_message = "keycloak.mode = vm needs one host with the role keycloak."
  }
}

check "cluster_for_addons" {
  assert {
    condition     = (var.keycloak.mode != "kubernetes" && !var.portal.enabled) || (var.cluster != null && local.first != "")
    error_message = "keycloak.mode = kubernetes and portal.enabled need the cluster (a server and var.cluster)."
  }
}
