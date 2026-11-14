# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# The RKE2 cluster: the first server, then the other two one after the other (etcd adds one
# member at a time), then the agents.

locals {
  rke2_stage = merge(local.common_stage, var.cluster == null ? {} : { token = var.cluster.token_file })
  node_ip    = { for n, h in var.hosts : n => h.internal_address != "" ? h.internal_address : h.address }
  server_url = local.first == "" ? "" : "https://${local.node_ip[local.first]}:9345"
  rke2_env = var.cluster == null ? {} : {
    for n in concat(local.servers, tolist(local.agents)) : n => merge(local.proxy_env, {
      ROLE             = contains(local.servers, n) ? "server" : "agent"
      SERVER_URL       = n == local.first ? "" : local.server_url
      NODE_NAME        = n
      NODE_IP          = local.node_ip[n]
      TLS_SAN          = join(",", distinct(concat([var.hosts[n].address], var.cluster.tls_san)))
      RKE2_VERSION     = var.cluster.rke2_version
      RKE2_CHANNEL     = var.cluster.rke2_channel
      INSTALL_URL      = var.cluster.install_url
      INGRESS          = var.cluster.ingress
      CIS              = tostring(var.cluster.cis)
      CLUSTER_CIDR     = var.cluster.cluster_cidr
      SERVICE_CIDR     = var.cluster.service_cidr
      DISABLE_FIREWALL = tostring(var.cluster.disable_firewall)
      MIRRORS          = local.mirrors
    })
  }
  rke2_nodes = keys(local.rke2_env)
  # the command that stages the files of a step: STEP -> map(stage name -> local path)
  stage_cmds = {
    for step, files in merge(
      { for n in local.rke2_nodes : "rke2-${n}" => local.rke2_stage },
      local.extra_stages,
      ) : step => join("\n", concat(
        ["set -eu", "umask 077", "d='${local.stage_root}/${step}/stage'", "rm -rf \"$d\"", "mkdir -p \"$d\""],
        [for name, f in files : "cp '${pathexpand(f)}' \"$d/${name}\""],
    ))
  }
  # how a step is run on its machine, as root, and its work dir removed
  run = {
    for step in keys(local.stage_cmds) : step => join(" ", [
      "W=/tmp/ngvm-tofu-${step};",
      "if [ \"$(id -u)\" -eq 0 ]; then S=; else S='sudo -n'; fi;",
      "$S bash $W/scripts/${split("-", step)[0] == "keycloak" ? "keycloak-${var.keycloak.mode == "vm" ? "vm" : "k8s"}" : split("-", step)[0]}.sh $W; rc=$?;",
      "$S rm -rf $W; exit $rc",
    ])
  }
}

resource "terraform_data" "rke2_first" {
  count = var.cluster == null || local.first == "" ? 0 : 1
  triggers_replace = {
    env     = local.rke2_env[local.first]
    scripts = local.scripts_hash
    rev     = var.revision
  }

  connection {
    type                = "ssh"
    host                = var.hosts[local.first].address
    user                = var.hosts[local.first].user
    port                = var.hosts[local.first].port
    private_key         = local.key
    agent               = local.key == null
    bastion_host        = try(var.ssh.bastion.host, null)
    bastion_user        = try(var.ssh.bastion.user, null)
    bastion_port        = try(var.ssh.bastion.port, null)
    bastion_private_key = local.key
    timeout             = "5m"
  }

  provisioner "local-exec" {
    command = local.stage_cmds["rke2-${local.first}"]
  }
  provisioner "remote-exec" {
    inline = ["rm -rf /tmp/ngvm-tofu-rke2-${local.first} && mkdir -m 700 /tmp/ngvm-tofu-rke2-${local.first}"]
  }
  provisioner "file" {
    source      = local.scripts
    destination = "/tmp/ngvm-tofu-rke2-${local.first}"
  }
  provisioner "file" {
    source      = "${local.stage_root}/rke2-${local.first}/stage"
    destination = "/tmp/ngvm-tofu-rke2-${local.first}"
  }
  provisioner "file" {
    content     = join("", [for k, v in local.rke2_env[local.first] : "${k}='${replace(v, "'", "'\\''")}'\n"])
    destination = "/tmp/ngvm-tofu-rke2-${local.first}/rke2.env"
  }
  provisioner "remote-exec" {
    inline = [local.run["rke2-${local.first}"]]
  }
  provisioner "local-exec" {
    command = "rm -rf '${local.stage_root}/rke2-${local.first}'"
  }
}

resource "terraform_data" "rke2_second" {
  count      = var.cluster == null || length(local.servers) < 3 ? 0 : 1
  depends_on = [terraform_data.rke2_first]
  triggers_replace = {
    env     = local.rke2_env[local.servers[1]]
    scripts = local.scripts_hash
    rev     = var.revision
  }

  connection {
    type                = "ssh"
    host                = var.hosts[local.servers[1]].address
    user                = var.hosts[local.servers[1]].user
    port                = var.hosts[local.servers[1]].port
    private_key         = local.key
    agent               = local.key == null
    bastion_host        = try(var.ssh.bastion.host, null)
    bastion_user        = try(var.ssh.bastion.user, null)
    bastion_port        = try(var.ssh.bastion.port, null)
    bastion_private_key = local.key
    timeout             = "5m"
  }

  provisioner "local-exec" {
    command = local.stage_cmds["rke2-${local.servers[1]}"]
  }
  provisioner "remote-exec" {
    inline = ["rm -rf /tmp/ngvm-tofu-rke2-${local.servers[1]} && mkdir -m 700 /tmp/ngvm-tofu-rke2-${local.servers[1]}"]
  }
  provisioner "file" {
    source      = local.scripts
    destination = "/tmp/ngvm-tofu-rke2-${local.servers[1]}"
  }
  provisioner "file" {
    source      = "${local.stage_root}/rke2-${local.servers[1]}/stage"
    destination = "/tmp/ngvm-tofu-rke2-${local.servers[1]}"
  }
  provisioner "file" {
    content     = join("", [for k, v in local.rke2_env[local.servers[1]] : "${k}='${replace(v, "'", "'\\''")}'\n"])
    destination = "/tmp/ngvm-tofu-rke2-${local.servers[1]}/rke2.env"
  }
  provisioner "remote-exec" {
    inline = [local.run["rke2-${local.servers[1]}"]]
  }
  provisioner "local-exec" {
    command = "rm -rf '${local.stage_root}/rke2-${local.servers[1]}'"
  }
}

resource "terraform_data" "rke2_third" {
  count      = var.cluster == null || length(local.servers) < 3 ? 0 : 1
  depends_on = [terraform_data.rke2_second]
  triggers_replace = {
    env     = local.rke2_env[local.servers[2]]
    scripts = local.scripts_hash
    rev     = var.revision
  }

  connection {
    type                = "ssh"
    host                = var.hosts[local.servers[2]].address
    user                = var.hosts[local.servers[2]].user
    port                = var.hosts[local.servers[2]].port
    private_key         = local.key
    agent               = local.key == null
    bastion_host        = try(var.ssh.bastion.host, null)
    bastion_user        = try(var.ssh.bastion.user, null)
    bastion_port        = try(var.ssh.bastion.port, null)
    bastion_private_key = local.key
    timeout             = "5m"
  }

  provisioner "local-exec" {
    command = local.stage_cmds["rke2-${local.servers[2]}"]
  }
  provisioner "remote-exec" {
    inline = ["rm -rf /tmp/ngvm-tofu-rke2-${local.servers[2]} && mkdir -m 700 /tmp/ngvm-tofu-rke2-${local.servers[2]}"]
  }
  provisioner "file" {
    source      = local.scripts
    destination = "/tmp/ngvm-tofu-rke2-${local.servers[2]}"
  }
  provisioner "file" {
    source      = "${local.stage_root}/rke2-${local.servers[2]}/stage"
    destination = "/tmp/ngvm-tofu-rke2-${local.servers[2]}"
  }
  provisioner "file" {
    content     = join("", [for k, v in local.rke2_env[local.servers[2]] : "${k}='${replace(v, "'", "'\\''")}'\n"])
    destination = "/tmp/ngvm-tofu-rke2-${local.servers[2]}/rke2.env"
  }
  provisioner "remote-exec" {
    inline = [local.run["rke2-${local.servers[2]}"]]
  }
  provisioner "local-exec" {
    command = "rm -rf '${local.stage_root}/rke2-${local.servers[2]}'"
  }
}

resource "terraform_data" "rke2_agent" {
  for_each   = var.cluster == null ? toset([]) : local.agents
  depends_on = [terraform_data.rke2_first]
  triggers_replace = {
    env     = local.rke2_env[each.key]
    scripts = local.scripts_hash
    rev     = var.revision
  }

  connection {
    type                = "ssh"
    host                = var.hosts[each.key].address
    user                = var.hosts[each.key].user
    port                = var.hosts[each.key].port
    private_key         = local.key
    agent               = local.key == null
    bastion_host        = try(var.ssh.bastion.host, null)
    bastion_user        = try(var.ssh.bastion.user, null)
    bastion_port        = try(var.ssh.bastion.port, null)
    bastion_private_key = local.key
    timeout             = "5m"
  }

  provisioner "local-exec" {
    command = local.stage_cmds["rke2-${each.key}"]
  }
  provisioner "remote-exec" {
    inline = ["rm -rf /tmp/ngvm-tofu-rke2-${each.key} && mkdir -m 700 /tmp/ngvm-tofu-rke2-${each.key}"]
  }
  provisioner "file" {
    source      = local.scripts
    destination = "/tmp/ngvm-tofu-rke2-${each.key}"
  }
  provisioner "file" {
    source      = "${local.stage_root}/rke2-${each.key}/stage"
    destination = "/tmp/ngvm-tofu-rke2-${each.key}"
  }
  provisioner "file" {
    content     = join("", [for k, v in local.rke2_env[each.key] : "${k}='${replace(v, "'", "'\\''")}'\n"])
    destination = "/tmp/ngvm-tofu-rke2-${each.key}/rke2.env"
  }
  provisioner "remote-exec" {
    inline = [local.run["rke2-${each.key}"]]
  }
  provisioner "local-exec" {
    command = "rm -rf '${local.stage_root}/rke2-${each.key}'"
  }
}

# The administrator's kubeconfig on the operator's machine (mode 600), the API on the first server.
resource "terraform_data" "kubeconfig" {
  count      = var.cluster == null || local.first == "" || try(var.cluster.kubeconfig_file, "") == "" ? 0 : 1
  depends_on = [terraform_data.rke2_first]
  triggers_replace = {
    first = terraform_data.rke2_first[0].id
  }
  provisioner "local-exec" {
    command = join(" ", concat(
      ["set -eu; umask 077; out='${pathexpand(var.cluster.kubeconfig_file)}'; mkdir -p \"$(dirname \"$out\")\";"],
      ["ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -p ${var.hosts[local.first].port}"],
      var.ssh.private_key_file == "" ? [] : ["-i '${pathexpand(var.ssh.private_key_file)}'"],
      try(var.ssh.bastion.host, null) == null ? [] : ["-J ${var.ssh.bastion.user}@${var.ssh.bastion.host}:${var.ssh.bastion.port}"],
      ["${var.hosts[local.first].user}@${var.hosts[local.first].address}",
        "'if [ \"$(id -u)\" -eq 0 ]; then cat /etc/rancher/rke2/rke2.yaml; else sudo -n cat /etc/rancher/rke2/rke2.yaml; fi'",
      "| sed 's#https://127.0.0.1:6443#https://${var.hosts[local.first].address}:6443#' > \"$out\""],
    ))
  }
}
