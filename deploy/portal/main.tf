# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
# A2VM client portal: one instance with the reporting database (PostgreSQL) and Grafana behind
# Caddy (HTTPS, Let's Encrypt). Configured at first boot by cloud-init (cloud-init.yaml.tftpl);
# secrets are generated on the instance and never pass through Terraform, its state or GitLab.

resource "scaleway_instance_ip" "portal" {}

resource "scaleway_instance_security_group" "portal" {
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

  dynamic "inbound_rule" {
    for_each = var.admin_ips
    content {
      action   = "accept"
      protocol = "TCP"
      port     = 5432
      ip_range = inbound_rule.value
    }
  }

  # Open to all for Let's Encrypt (TLS-ALPN challenge); Caddy answers 403 outside admin_ips.
  inbound_rule {
    action   = "accept"
    protocol = "TCP"
    port     = 443
    ip_range = "0.0.0.0/0"
  }
}

resource "scaleway_instance_server" "portal" {
  name              = var.name
  type              = var.instance_type
  image             = var.image
  ip_id             = scaleway_instance_ip.portal.id
  security_group_id = scaleway_instance_security_group.portal.id
  tags              = ["a2vm", "portal"]

  root_volume {
    size_in_gb = var.root_volume_gb
  }

  user_data = {
    cloud-init = templatefile("${path.module}/cloud-init.yaml.tftpl", {
      domain         = var.domain
      admin_ips      = var.admin_ips
      postgres_image = var.postgres_image
      grafana_image  = var.grafana_image
      caddy_image    = var.caddy_image
    })
  }
}
