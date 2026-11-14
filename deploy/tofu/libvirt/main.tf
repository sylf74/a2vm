# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# VMs on a bare KVM host (libvirt), then the platform on them (docs/platform.md §8). Static
# addresses through cloud-init; the image of each system downloaded once into the pool.

resource "libvirt_volume" "base" {
  for_each = toset(distinct([for m in var.machines : m.os]))
  name     = "${var.name}-${each.key}-base.qcow2"
  pool     = var.pool
  source   = var.images[each.key]
  format   = "qcow2"
}

resource "libvirt_volume" "disk" {
  for_each       = var.machines
  name           = "${var.name}-${each.key}.qcow2"
  pool           = var.pool
  base_volume_id = libvirt_volume.base[each.value.os].id
  size           = each.value.disk_gb * 1073741824
  format         = "qcow2"
}

resource "libvirt_cloudinit_disk" "init" {
  for_each = var.machines
  name     = "${var.name}-${each.key}-init.iso"
  pool     = var.pool
  user_data = templatefile("${path.module}/user-data.yaml.tftpl", {
    hostname   = each.key
    user       = var.admin_user
    public_key = trimspace(file(pathexpand(var.ssh_public_key_file)))
  })
  network_config = templatefile("${path.module}/network-config.yaml.tftpl", {
    address = each.value.address
    gateway = var.gateway
    dns     = var.dns
  })
}

resource "libvirt_domain" "m" {
  for_each  = var.machines
  name      = "${var.name}-${each.key}"
  vcpu      = each.value.vcpu
  memory    = each.value.memory_mb
  autostart = true
  cloudinit = libvirt_cloudinit_disk.init[each.key].id

  cpu {
    mode = "host-passthrough" # Rocky Linux 10 needs x86-64-v3
  }
  network_interface {
    bridge       = var.bridge == "" ? null : var.bridge
    network_name = var.bridge == "" ? var.network_name : null
  }
  disk {
    volume_id = libvirt_volume.disk[each.key].id
  }
  console {
    type        = "pty"
    target_type = "serial"
    target_port = "0"
  }
}

locals {
  hosts = {
    for n, m in var.machines : n => {
      address       = split("/", m.address)[0]
      user          = var.admin_user
      roles         = m.roles
      physical_host = var.physical_host
    }
  }
}

module "platform" {
  source     = "../modules/platform"
  depends_on = [libvirt_domain.m]

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
