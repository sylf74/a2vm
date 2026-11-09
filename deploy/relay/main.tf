# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
# A2VM relay of the public sources (v0.23.4, topology R of docs/hld/proposals/intel-placement.md):
# one small instance with Caddy, one route per allowed upstream host and nothing else. Not a forward
# proxy, not a tunnel: no CONNECT, no open destination. Configured at first boot by cloud-init
# (cloud-init.yaml.tftpl); its token is generated on the instance and never passes through
# Terraform, its state or GitLab.

data "scaleway_instance_ip" "kept" {
  count   = var.ip_address == "" ? 0 : 1
  address = var.ip_address
}

resource "scaleway_instance_ip" "relay" {
  count = var.ip_address == "" ? 1 : 0
}

locals {
  ip_id      = var.ip_address == "" ? scaleway_instance_ip.relay[0].id : data.scaleway_instance_ip.kept[0].id
  ip_address = var.ip_address == "" ? scaleway_instance_ip.relay[0].address : var.ip_address
}

resource "scaleway_instance_security_group" "relay" {
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

  # Open to all for Let's Encrypt (TLS-ALPN challenge); Caddy answers 403 outside allowed_ips.
  inbound_rule {
    action   = "accept"
    protocol = "TCP"
    port     = 443
    ip_range = "0.0.0.0/0"
  }
}

resource "scaleway_instance_server" "relay" {
  name              = var.name
  type              = var.instance_type
  image             = var.image
  ip_id             = local.ip_id
  security_group_id = scaleway_instance_security_group.relay.id
  tags              = ["a2vm", "relay"]

  root_volume {
    size_in_gb = var.root_volume_gb
  }

  user_data = {
    cloud-init = templatefile("${path.module}/cloud-init.yaml.tftpl", {
      domain      = var.domain
      allowed_ips = var.allowed_ips
      hosts       = var.hosts
      caddy_image = var.caddy_image
    })
  }
}
