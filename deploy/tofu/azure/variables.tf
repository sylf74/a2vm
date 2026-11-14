# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
variable "name" {
  description = "Prefix of every resource."
  type        = string
  default     = "ngvm"
}

variable "subscription_id" {
  description = "Azure subscription."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "francecentral"
}

variable "address_space" {
  description = "Address space of the virtual network; the machines are in its first /24."
  type        = string
  default     = "10.60.0.0/16"
}

variable "machines" {
  description = "The VMs, by name, with their roles (as modules/platform hosts). os: ubuntu or rocky."
  type = map(object({
    roles   = list(string)
    size    = optional(string, "Standard_D2s_v5")
    os      = optional(string, "ubuntu")
    disk_gb = optional(number, 64)
  }))
  validation {
    condition     = alltrue([for m in var.machines : contains(["ubuntu", "rocky"], m.os)])
    error_message = "machines: os is ubuntu or rocky."
  }
}

variable "images" {
  description = "Image per os. plan: the marketplace plan (Rocky Linux), whose terms are accepted once: az vm image terms accept --publisher resf --offer rockylinux-x86_64 --plan 9-base."
  type = map(object({
    publisher = string
    offer     = string
    sku       = string
    version   = optional(string, "latest")
    plan      = optional(bool, false)
  }))
  default = {
    ubuntu = { publisher = "Canonical", offer = "ubuntu-24_04-lts", sku = "server" }
    rocky  = { publisher = "resf", offer = "rockylinux-x86_64", sku = "9-base", plan = true }
  }
}

variable "admin_user" {
  description = "The administrator of the VMs (passwordless sudo)."
  type        = string
  default     = "ngvm"
}

variable "ssh_public_key_file" {
  description = "Public key of the administrator (its private key in platform.ssh.private_key_file, or in the SSH agent)."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "admin_cidrs" {
  description = "Addresses (CIDR) allowed to SSH and to reach the Kubernetes API: the operator's."
  type        = list(string)
  validation {
    condition     = length(var.admin_cidrs) > 0 && alltrue([for c in var.admin_cidrs : can(cidrhost(c, 0))])
    error_message = "admin_cidrs: at least one CIDR, e.g. 203.0.113.10/32."
  }
}

variable "public_cidrs" {
  description = "Addresses (CIDR) allowed on 80 and 443 (the ingress). Empty: admin_cidrs only."
  type        = list(string)
  default     = []
}

variable "platform" {
  description = "The rest of the platform, as the variables of modules/platform except hosts."
  type        = any
  default     = {}
}
