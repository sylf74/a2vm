# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
variable "name" {
  description = "Prefix of every resource."
  type        = string
  default     = "ngvm"
}

variable "project_id" {
  description = "Scaleway project; empty: SCW_DEFAULT_PROJECT_ID."
  type        = string
  default     = ""
}

variable "zone" {
  description = "Scaleway zone."
  type        = string
  default     = "fr-par-1"
}

variable "machines" {
  description = "The instances, by name, with their roles (as modules/platform hosts). os: ubuntu or rocky."
  type = map(object({
    roles   = list(string)
    type    = optional(string, "DEV1-L")
    os      = optional(string, "ubuntu")
    disk_gb = optional(number, 40)
  }))
  validation {
    condition     = alltrue([for m in var.machines : contains(["ubuntu", "rocky"], m.os)])
    error_message = "machines: os is ubuntu or rocky."
  }
}

variable "images" {
  description = "Scaleway image label per os (scw marketplace image list)."
  type        = map(string)
  default     = { ubuntu = "ubuntu_noble", rocky = "rockylinux_10" }
}

variable "private_subnet" {
  description = "Subnet of the private network that carries the cluster's traffic."
  type        = string
  default     = "172.16.32.0/22"
}

variable "ssh_public_key_file" {
  description = "Public key put on the instances (its private key in platform.ssh.private_key_file, or in the SSH agent)."
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
  description = "Addresses (CIDR) allowed on 80 and 443 (the ingress: portal, collectors' push, Keycloak). Empty: admin_cidrs only."
  type        = list(string)
  default     = []
}

variable "platform" {
  description = "The rest of the platform, as the variables of modules/platform except hosts: ssh, network, cluster, addons, portal, registry, collectors (host: a machine's name), keycloak, secrets_dir, revision."
  type        = any
  default     = {}
}
