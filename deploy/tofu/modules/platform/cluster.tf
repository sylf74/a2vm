# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# What runs in the cluster, from the first server once the cluster is up: the addons, Keycloak
# (mode kubernetes), the portal. Each step waits for the one before.

locals {
  in_cluster = var.cluster != null && local.first != ""
  first_conn = local.in_cluster ? var.hosts[local.first] : null

  addons_stage = merge(
    var.addons.issuer == "ca" ? { "issuer-ca.crt" = var.addons.issuer_ca_cert_file, "issuer-ca.key" = var.addons.issuer_ca_key_file } : {},
    var.addons.gitlab_agent == null ? {} : merge(
      { "agent-token" = var.addons.gitlab_agent.token_file },
      var.addons.gitlab_agent.ca_file == "" ? {} : { "gitlab-ca.pem" = var.addons.gitlab_agent.ca_file },
    ),
  )
  addons_env = merge(local.proxy_env, {
    HELM_VERSION         = var.addons.helm_version
    HELM_URL             = var.addons.helm_url
    STORAGE              = var.addons.storage
    LOCAL_PATH_URL       = var.addons.local_path_url
    CERT_MANAGER         = tostring(var.addons.cert_manager)
    CERT_MANAGER_CHART   = var.addons.cert_manager_chart
    CERT_MANAGER_VERSION = var.addons.cert_manager_version
    ISSUER               = var.addons.issuer
    ISSUER_NAME          = var.addons.issuer_name
    ACME_EMAIL           = var.addons.acme_email
    ACME_SERVER          = var.addons.acme_server
    INGRESS_CLASS        = try(var.cluster.ingress, "ingress-nginx") == "traefik" ? "traefik" : "nginx"
    CNPG                 = tostring(var.addons.cnpg)
    CNPG_URL             = var.addons.cnpg_url
    AGENT                = tostring(var.addons.gitlab_agent != null)
    AGENT_NAME           = try(var.addons.gitlab_agent.name, "")
    KAS_ADDRESS          = try(var.addons.gitlab_agent.kas_address, "")
    AGENT_CHART_REPO     = try(var.addons.gitlab_agent.chart_repo, "")
    AGENT_VERSION        = try(var.addons.gitlab_agent.version, "")
  })

  portal_stage = merge(
    { "portal-values.yaml" = var.portal.values_file },
    local.registry_stage,
    local.portal_oidc_secret == "" ? {} : { "oidc-client-secret" = local.portal_oidc_secret },
  )
  portal_env = merge(local.proxy_env, {
    NAMESPACE = var.portal.namespace
    RELEASE   = var.portal.release
    REGISTRY  = var.registry.host
  })

  keycloak_stage = var.keycloak.mode == "vm" ? merge(
    local.common_stage,
    var.keycloak.tls == "files" ? { "tls.crt" = var.keycloak.tls_cert_file, "tls.key" = var.keycloak.tls_key_file } : {},
  ) : {}
  keycloak_env = merge(local.proxy_env, {
    PUBLIC_HOST    = var.keycloak.hostname
    REALM          = var.keycloak.realm
    CLIENTS        = local.kc_clients
    KC_GROUPS      = join(";", var.keycloak.groups)
    TLS            = var.keycloak.tls
    ACME_EMAIL     = var.keycloak.acme_email
    KEYCLOAK_IMAGE = var.keycloak.mode == "vm" ? var.keycloak.keycloak_image : ""
    POSTGRES_IMAGE = var.keycloak.postgres_image
    CADDY_IMAGE    = var.keycloak.caddy_image
    OPERATOR_URL   = var.keycloak.operator_url
    NAMESPACE      = var.keycloak.namespace
    INGRESS_CLASS  = var.keycloak.ingress_class
    CLUSTER_ISSUER = var.keycloak.cluster_issuer
    TLS_SECRET     = var.keycloak.tls_secret
    STORAGE_SIZE   = var.keycloak.storage_size
  })
  # the machine where Keycloak's script runs, and so where the clients' secrets are
  keycloak_conn = (
    var.keycloak.mode == "vm" && local.kc_host != null ? var.hosts[local.kc_host] :
    var.keycloak.mode == "kubernetes" ? local.first_conn : null
  )

  extra_stages = merge(
    local.in_cluster ? { addons = local.addons_stage } : {},
    var.portal.enabled ? { portal = local.portal_stage } : {},
    var.keycloak.mode != "none" ? { keycloak = local.keycloak_stage } : {},
    { for n, c in var.collectors : "collector-${n}" => local.collector_stage[n] },
  )
}

resource "terraform_data" "addons" {
  count      = local.in_cluster ? 1 : 0
  depends_on = [terraform_data.rke2_first, terraform_data.rke2_second, terraform_data.rke2_third, terraform_data.rke2_agent]
  triggers_replace = {
    env     = local.addons_env
    files   = keys(local.addons_stage)
    scripts = local.scripts_hash
    rev     = var.revision
  }

  connection {
    type                = "ssh"
    host                = local.first_conn.address
    user                = local.first_conn.user
    port                = local.first_conn.port
    private_key         = local.key
    agent               = local.key == null
    bastion_host        = try(var.ssh.bastion.host, null)
    bastion_user        = try(var.ssh.bastion.user, null)
    bastion_port        = try(var.ssh.bastion.port, null)
    bastion_private_key = local.key
    timeout             = "5m"
  }

  provisioner "local-exec" {
    command = local.stage_cmds["addons"]
  }
  provisioner "remote-exec" {
    inline = ["rm -rf /tmp/ngvm-tofu-addons && mkdir -m 700 /tmp/ngvm-tofu-addons"]
  }
  provisioner "file" {
    source      = local.scripts
    destination = "/tmp/ngvm-tofu-addons"
  }
  provisioner "file" {
    source      = "${local.stage_root}/addons/stage"
    destination = "/tmp/ngvm-tofu-addons"
  }
  provisioner "file" {
    content     = join("", [for k, v in local.addons_env : "${k}='${replace(v, "'", "'\\''")}'\n"])
    destination = "/tmp/ngvm-tofu-addons/addons.env"
  }
  provisioner "remote-exec" {
    inline = [local.run["addons"]]
  }
  provisioner "local-exec" {
    command = "rm -rf '${local.stage_root}/addons'"
  }
}

resource "terraform_data" "keycloak" {
  count      = var.keycloak.mode == "none" ? 0 : 1
  depends_on = [terraform_data.addons]
  triggers_replace = {
    env     = local.keycloak_env
    mode    = var.keycloak.mode
    files   = keys(local.keycloak_stage)
    scripts = local.scripts_hash
    rev     = var.revision
  }

  connection {
    type                = "ssh"
    host                = local.keycloak_conn.address
    user                = local.keycloak_conn.user
    port                = local.keycloak_conn.port
    private_key         = local.key
    agent               = local.key == null
    bastion_host        = try(var.ssh.bastion.host, null)
    bastion_user        = try(var.ssh.bastion.user, null)
    bastion_port        = try(var.ssh.bastion.port, null)
    bastion_private_key = local.key
    timeout             = "5m"
  }

  provisioner "local-exec" {
    command = local.stage_cmds["keycloak"]
  }
  provisioner "remote-exec" {
    inline = ["rm -rf /tmp/ngvm-tofu-keycloak && mkdir -m 700 /tmp/ngvm-tofu-keycloak"]
  }
  provisioner "file" {
    source      = local.scripts
    destination = "/tmp/ngvm-tofu-keycloak"
  }
  provisioner "file" {
    source      = "${local.stage_root}/keycloak/stage"
    destination = "/tmp/ngvm-tofu-keycloak"
  }
  provisioner "file" {
    content     = join("", [for k, v in local.keycloak_env : "${k}='${replace(v, "'", "'\\''")}'\n"])
    destination = "/tmp/ngvm-tofu-keycloak/keycloak.env"
  }
  provisioner "remote-exec" {
    inline = [local.run["keycloak"]]
  }
  # the secrets of the clients Keycloak made, to the operator's machine (mode 600)
  provisioner "local-exec" {
    command = join("\n", concat(
      ["set -eu", "umask 077", "rm -rf '${local.stage_root}/keycloak'", "d='${local.secrets_dir}/keycloak'", "mkdir -p \"$d\""],
      [for id in keys(var.keycloak.clients) : join(" ", concat(
        ["ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -p ${local.keycloak_conn.port}"],
        var.ssh.private_key_file == "" ? [] : ["-i '${pathexpand(var.ssh.private_key_file)}'"],
        try(var.ssh.bastion.host, null) == null ? [] : ["-J ${var.ssh.bastion.user}@${var.ssh.bastion.host}:${var.ssh.bastion.port}"],
        ["${local.keycloak_conn.user}@${local.keycloak_conn.address}",
          "'f=/etc/ngvm/keycloak/clients/${id}.secret; if [ \"$(id -u)\" -eq 0 ]; then cat $f; else sudo -n cat $f; fi'",
        "> \"$d/${id}.secret\""],
      ))],
    ))
  }
}

resource "terraform_data" "portal" {
  count      = var.portal.enabled && local.in_cluster ? 1 : 0
  depends_on = [terraform_data.addons, terraform_data.keycloak]
  triggers_replace = {
    env     = local.portal_env
    values  = filesha256(pathexpand(var.portal.values_file))
    chart   = sha256(join("", [for f in sort(fileset(local.portal_chart, "**")) : filesha256("${local.portal_chart}/${f}")]))
    files   = keys(local.portal_stage)
    scripts = local.scripts_hash
    rev     = var.revision
  }

  connection {
    type                = "ssh"
    host                = local.first_conn.address
    user                = local.first_conn.user
    port                = local.first_conn.port
    private_key         = local.key
    agent               = local.key == null
    bastion_host        = try(var.ssh.bastion.host, null)
    bastion_user        = try(var.ssh.bastion.user, null)
    bastion_port        = try(var.ssh.bastion.port, null)
    bastion_private_key = local.key
    timeout             = "5m"
  }

  provisioner "local-exec" {
    command = local.stage_cmds["portal"]
  }
  provisioner "remote-exec" {
    inline = ["rm -rf /tmp/ngvm-tofu-portal && mkdir -m 700 /tmp/ngvm-tofu-portal /tmp/ngvm-tofu-portal/charts"]
  }
  provisioner "file" {
    source      = local.scripts
    destination = "/tmp/ngvm-tofu-portal"
  }
  provisioner "file" {
    source      = local.portal_chart
    destination = "/tmp/ngvm-tofu-portal/charts"
  }
  provisioner "file" {
    source      = "${local.stage_root}/portal/stage"
    destination = "/tmp/ngvm-tofu-portal"
  }
  provisioner "file" {
    content     = join("", [for k, v in local.portal_env : "${k}='${replace(v, "'", "'\\''")}'\n"])
    destination = "/tmp/ngvm-tofu-portal/portal.env"
  }
  provisioner "remote-exec" {
    inline = [local.run["portal"]]
  }
  provisioner "local-exec" {
    command = "rm -rf '${local.stage_root}/portal'"
  }
}

locals {
  portal_chart = "${path.module}/../../../charts/ngvm-portal"
}
