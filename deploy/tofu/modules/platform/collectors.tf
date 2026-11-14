# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# The collectors, each on its host (any host, with or without the cluster): Podman, the files of
# collector.yaml, one timer per connector (docs/collectors.md).

locals {
  collector_stage = {
    for n, c in var.collectors : n => merge(
      local.common_stage,
      local.registry_stage,
      c.files,
      { "collector.yaml" = c.config_file },
      c.gvm_env_file == "" ? {} : { "gvm.env" = c.gvm_env_file },
    )
  }
  collector_env = {
    for n, c in var.collectors : n => merge(local.proxy_env, {
      TENANT             = c.tenant
      COLLECTOR          = n
      IMAGE              = c.image
      CONNECTORS         = join(";", [for name, when in c.connectors : "${name}=${when}"])
      CONTAINER_PROXY    = tostring(c.container_proxy)
      OPENVAS_SOCKET_DIR = c.openvas_socket_dir
      LEGACY_CLEANUP     = tostring(c.legacy_cleanup)
    })
  }
}

check "collector_hosts" {
  assert {
    condition     = alltrue([for c in var.collectors : contains(keys(var.hosts), c.host)])
    error_message = "collectors: each host must be one of var.hosts."
  }
}

resource "terraform_data" "collector" {
  for_each = var.collectors
  triggers_replace = {
    env     = local.collector_env[each.key]
    config  = filesha256(pathexpand(each.value.config_file))
    files   = keys(local.collector_stage[each.key])
    scripts = local.scripts_hash
    rev     = var.revision
  }

  connection {
    type                = "ssh"
    host                = var.hosts[each.value.host].address
    user                = var.hosts[each.value.host].user
    port                = var.hosts[each.value.host].port
    private_key         = local.key
    agent               = local.key == null
    bastion_host        = try(var.ssh.bastion.host, null)
    bastion_user        = try(var.ssh.bastion.user, null)
    bastion_port        = try(var.ssh.bastion.port, null)
    bastion_private_key = local.key
    timeout             = "5m"
  }

  provisioner "local-exec" {
    command = local.stage_cmds["collector-${each.key}"]
  }
  provisioner "remote-exec" {
    inline = ["rm -rf /tmp/ngvm-tofu-collector-${each.key} && mkdir -m 700 /tmp/ngvm-tofu-collector-${each.key}"]
  }
  provisioner "file" {
    source      = local.scripts
    destination = "/tmp/ngvm-tofu-collector-${each.key}"
  }
  provisioner "file" {
    source      = "${local.stage_root}/collector-${each.key}/stage"
    destination = "/tmp/ngvm-tofu-collector-${each.key}"
  }
  provisioner "file" {
    content     = join("", [for k, v in local.collector_env[each.key] : "${k}='${replace(v, "'", "'\\''")}'\n"])
    destination = "/tmp/ngvm-tofu-collector-${each.key}/collector.env"
  }
  provisioner "remote-exec" {
    inline = [local.run["collector-${each.key}"]]
  }
  provisioner "local-exec" {
    command = "rm -rf '${local.stage_root}/collector-${each.key}'"
  }
}
