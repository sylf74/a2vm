# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
variable "name" {
  description = "Prefix of every resource."
  type        = string
  default     = "ngvm"
}

variable "libvirt_uri" {
  description = "The KVM host, e.g. qemu+ssh://root@kvm01.example.org/system (a bare Rocky Linux 10 with libvirt)."
  type        = string
}

variable "physical_host" {
  description = "Name of the KVM host: two RKE2 servers are never put on the same machine."
  type        = string
  default     = "kvm"
}

variable "pool" {
  description = "Storage pool of the KVM host."
  type        = string
  default     = "default"
}

variable "bridge" {
  description = "Bridge of the KVM host the VMs are on (their addresses on the LAN). Empty: the libvirt network `network_name` (NAT: reach the VMs through the KVM host, platform.ssh.bastion)."
  type        = string
  default     = ""
}

variable "network_name" {
  description = "libvirt network when bridge is empty."
  type        = string
  default     = "default"
}

variable "images" {
  description = "Cloud image per os (qcow2), downloaded once into the pool."
  type        = map(string)
  default = {
    ubuntu = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
    rocky  = "https://dl.rockylinux.org/pub/rocky/10/images/x86_64/Rocky-10-GenericCloud-Base.latest.x86_64.qcow2"
  }
}

variable "machines" {
  description = "The VMs, by name, with their roles (as modules/platform hosts). address: static, with its prefix (192.0.2.41/24). os: ubuntu or rocky."
  type = map(object({
    roles     = list(string)
    address   = string
    os        = optional(string, "rocky")
    vcpu      = optional(number, 2)
    memory_mb = optional(number, 4096)
    disk_gb   = optional(number, 40)
  }))
  validation {
    condition     = alltrue([for m in var.machines : contains(["ubuntu", "rocky"], m.os) && can(cidrhost(m.address, 0))])
    error_message = "machines: os is ubuntu or rocky; address with its prefix, e.g. 192.0.2.41/24."
  }
}

variable "gateway" {
  description = "Default gateway of the VMs."
  type        = string
}

variable "dns" {
  description = "DNS servers of the VMs."
  type        = list(string)
}

variable "admin_user" {
  description = "The administrator of the VMs (passwordless sudo)."
  type        = string
  default     = "ngvm"
}

variable "ssh_public_key_file" {
  description = "Public key of the administrator."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "platform" {
  description = "The rest of the platform, as the variables of modules/platform except hosts."
  type        = any
  default     = {}
}
