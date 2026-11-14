# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# Instances on Scaleway, then the platform on them (docs/platform.md §8). The cluster's traffic
# goes through a private network; SSH and the API are open to admin_cidrs only.

resource "scaleway_iam_ssh_key" "ngvm" {
  name       = var.name
  public_key = trimspace(file(pathexpand(var.ssh_public_key_file)))
  project_id = var.project_id == "" ? null : var.project_id
}

resource "scaleway_vpc_private_network" "ngvm" {
  name = var.name
  ipv4_subnet {
    subnet = var.private_subnet
  }
}

resource "scaleway_instance_ip" "m" {
  for_each = var.machines
}

resource "scaleway_instance_security_group" "ngvm" {
  name                    = "${var.name}-sg"
  inbound_default_policy  = "drop"
  outbound_default_policy = "accept"
  stateful                = true

  dynamic "inbound_rule" {
    for_each = setproduct(var.admin_cidrs, [22, 6443, 80, 443])
    content {
      action   = "accept"
      protocol = "TCP"
      port     = inbound_rule.value[1]
      ip_range = inbound_rule.value[0]
    }
  }
  dynamic "inbound_rule" {
    for_each = setproduct(var.public_cidrs, [80, 443])
    content {
      action   = "accept"
      protocol = "TCP"
      port     = inbound_rule.value[1]
      ip_range = inbound_rule.value[0]
    }
  }
}

resource "scaleway_instance_server" "m" {
  for_each          = var.machines
  name              = "${var.name}-${each.key}"
  type              = each.value.type
  image             = var.images[each.value.os]
  ip_id             = scaleway_instance_ip.m[each.key].id
  security_group_id = scaleway_instance_security_group.ngvm.id
  tags              = concat([var.name], each.value.roles)

  root_volume {
    size_in_gb = each.value.disk_gb
  }
  private_network {
    pn_id = scaleway_vpc_private_network.ngvm.id
  }
  depends_on = [scaleway_iam_ssh_key.ngvm]
}

data "scaleway_ipam_ip" "m" {
  for_each    = var.machines
  mac_address = scaleway_instance_server.m[each.key].private_network[0].mac_address
  type        = "ipv4"
}

locals {
  hosts = {
    for n, m in var.machines : n => {
      address          = scaleway_instance_ip.m[n].address
      internal_address = data.scaleway_ipam_ip.m[n].address
      user             = "root"
      roles            = m.roles
    }
  }
}

module "platform" {
  source = "../modules/platform"

  hosts       = local.hosts
  ssh         = try(var.platform.ssh, {})
  network     = try(var.platform.network, {})
  cluster     = try(var.platform.cluster, null)
  addons      = try(var.platform.addons, {})
  portal      = try(var.platform.portal, {})
  registry    = try(var.platform.registry, {})
  collectors  = try(var.platform.collectors, {})
  keycloak    = try(var.platform.keycloak, {})
  secrets_dir = try(var.platform.secrets_dir, "~/.ngvm/secrets")
  revision    = try(var.platform.revision, "1")
}
