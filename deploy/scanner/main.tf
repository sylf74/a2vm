# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
# A2VM cloud scanner: one instance with Greenbone Community Edition in containers and the GitLab
# runner of the client's external project (docs/openvas.md §5). Configured at first boot by
# cloud-init (cloud-init.yaml.tftpl). The GMP password is generated on the instance; the runner's
# token is sent over SSH after the first boot (README.md): no secret passes through Terraform, its
# state or the instance's metadata.

# A flexible IP kept from an earlier instance (allowed by the reverse proxy, known by the targets),
# or a new one.
data "scaleway_instance_ip" "kept" {
  count   = var.ip_address == "" ? 0 : 1
  address = var.ip_address
}

resource "scaleway_instance_ip" "scanner" {
  count = var.ip_address == "" ? 1 : 0
}

locals {
  ip_id      = var.ip_address == "" ? scaleway_instance_ip.scanner[0].id : data.scaleway_instance_ip.kept[0].id
  ip_address = var.ip_address == "" ? scaleway_instance_ip.scanner[0].address : var.ip_address
}

# Inbound: SSH from the admin addresses only. Outbound: open, the scans go out.
resource "scaleway_instance_security_group" "scanner" {
  name                    = "${var.name}-sg"
  inbound_default_policy  = "drop"
  outbound_default_policy = "accept"
  stateful                = true

  dynamic "inbound_rule" {
    for_each = var.admin_ips
    content {
      action   = "accept"
      protocol = "TCP"
      port     = 22
      ip_range = inbound_rule.value
    }
  }
}

resource "scaleway_instance_server" "scanner" {
  name              = var.name
  type              = var.instance_type
  image             = var.image
  ip_id             = local.ip_id
  security_group_id = scaleway_instance_security_group.scanner.id
  tags              = ["a2vm", "scanner"]

  root_volume {
    size_in_gb = var.root_volume_gb
  }

  user_data = {
    cloud-init = templatefile("${path.module}/cloud-init.yaml.tftpl", {
      gitlab_url            = var.gitlab_url
      runner_tag            = var.runner_tag
      greenbone_compose_url = var.greenbone_compose_url
      feed_update_time      = var.feed_update_time
    })
  }
}
