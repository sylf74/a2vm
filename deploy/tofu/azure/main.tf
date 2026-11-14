# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# VMs on Azure, then the platform on them (docs/platform.md §8). The cluster's traffic stays in
# the virtual network; SSH and the API are open to admin_cidrs only.

resource "azurerm_resource_group" "ngvm" {
  name     = "${var.name}-rg"
  location = var.location
}

resource "azurerm_virtual_network" "ngvm" {
  name                = "${var.name}-vnet"
  resource_group_name = azurerm_resource_group.ngvm.name
  location            = azurerm_resource_group.ngvm.location
  address_space       = [var.address_space]
}

resource "azurerm_subnet" "ngvm" {
  name                 = "${var.name}-machines"
  resource_group_name  = azurerm_resource_group.ngvm.name
  virtual_network_name = azurerm_virtual_network.ngvm.name
  address_prefixes     = [cidrsubnet(var.address_space, 8, 0)]
}

resource "azurerm_network_security_group" "ngvm" {
  name                = "${var.name}-nsg"
  resource_group_name = azurerm_resource_group.ngvm.name
  location            = azurerm_resource_group.ngvm.location

  security_rule {
    name                       = "admin"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["22", "6443", "80", "443"]
    source_address_prefixes    = var.admin_cidrs
    destination_address_prefix = "*"
  }
  dynamic "security_rule" {
    for_each = length(var.public_cidrs) == 0 ? [] : [1]
    content {
      name                       = "public"
      priority                   = 110
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_ranges    = ["80", "443"]
      source_address_prefixes    = var.public_cidrs
      destination_address_prefix = "*"
    }
  }
}

resource "azurerm_subnet_network_security_group_association" "ngvm" {
  subnet_id                 = azurerm_subnet.ngvm.id
  network_security_group_id = azurerm_network_security_group.ngvm.id
}

resource "azurerm_public_ip" "m" {
  for_each            = var.machines
  name                = "${var.name}-${each.key}-ip"
  resource_group_name = azurerm_resource_group.ngvm.name
  location            = azurerm_resource_group.ngvm.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_interface" "m" {
  for_each            = var.machines
  name                = "${var.name}-${each.key}-nic"
  resource_group_name = azurerm_resource_group.ngvm.name
  location            = azurerm_resource_group.ngvm.location

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.ngvm.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.m[each.key].id
  }
}

resource "azurerm_linux_virtual_machine" "m" {
  for_each              = var.machines
  name                  = "${var.name}-${each.key}"
  computer_name         = each.key
  resource_group_name   = azurerm_resource_group.ngvm.name
  location              = azurerm_resource_group.ngvm.location
  size                  = each.value.size
  admin_username        = var.admin_user
  network_interface_ids = [azurerm_network_interface.m[each.key].id]
  tags                  = { product = var.name, roles = join(" ", each.value.roles) }

  admin_ssh_key {
    username   = var.admin_user
    public_key = trimspace(file(pathexpand(var.ssh_public_key_file)))
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_size_gb         = each.value.disk_gb
  }
  source_image_reference {
    publisher = var.images[each.value.os].publisher
    offer     = var.images[each.value.os].offer
    sku       = var.images[each.value.os].sku
    version   = var.images[each.value.os].version
  }
  dynamic "plan" {
    for_each = var.images[each.value.os].plan ? [1] : []
    content {
      publisher = var.images[each.value.os].publisher
      product   = var.images[each.value.os].offer
      name      = var.images[each.value.os].sku
    }
  }
  depends_on = [azurerm_subnet_network_security_group_association.ngvm]
}

locals {
  hosts = {
    for n, m in var.machines : n => {
      address          = azurerm_public_ip.m[n].ip_address
      internal_address = azurerm_linux_virtual_machine.m[n].private_ip_address
      user             = var.admin_user
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
