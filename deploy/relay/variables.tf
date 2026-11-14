# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
variable "name" {
  description = "Instance name (also its host name)."
  type        = string
  default     = "ngvm-relay"
}

variable "domain" {
  description = "Public DNS name of the relay. The DNS record is created by hand; Let's Encrypt needs it before the first request."
  type        = string
}

variable "allowed_ips" {
  description = "Addresses (CIDR) allowed to use the relay: the corporate egress addresses (as the target sites would see them)."
  type        = list(string)
  validation {
    condition     = length(var.allowed_ips) > 0 && alltrue([for c in var.allowed_ips : can(cidrhost(c, 0))])
    error_message = "allowed_ips: at least one CIDR, e.g. 203.0.113.10/32."
  }
}

variable "admin_ips" {
  description = "Addresses (CIDR) allowed to SSH."
  type        = list(string)
  validation {
    condition     = length(var.admin_ips) > 0 && alltrue([for c in var.admin_ips : can(cidrhost(c, 0))])
    error_message = "admin_ips: at least one CIDR, e.g. 203.0.113.10/32."
  }
}

variable "hosts" {
  description = "The upstream hosts the relay reaches, one route each (https only). Keep it equal to NGVM_RELAY_HOSTS. Never an authenticated API (GTI, Microsoft Graph, an LLM)."
  type        = list(string)
  default = [
    "raw.githubusercontent.com", "www.cisa.gov", "api.first.org", "www.cert.ssi.gouv.fr", "cveawg.mitre.org",
    "access.redhat.com", "api.osv.dev", "osv-vulnerabilities.storage.googleapis.com", "ubuntu.com", "msrc.microsoft.com", "api.msrc.microsoft.com",
    "sec.cloudapps.cisco.com", "www.cisco.com", "www.fortiguard.com", "security.paloaltonetworks.com",
    "support.hpe.com", "cert-portal.siemens.com", "wid.cert-bund.de", "cert.europa.eu", "www.jpcert.or.jp",
    "www.zerodayinitiative.com", "seclists.org", "www.rapid7.com", "www.horizon3.ai", "labs.watchtowr.com",
    "www.bleepingcomputer.com",
  ]
  validation {
    condition     = alltrue([for h in var.hosts : can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", h))])
    error_message = "hosts: host names only, lower case, no scheme nor path."
  }
}

variable "project_id" {
  description = "Scaleway project; empty: SCW_DEFAULT_PROJECT_ID."
  type        = string
  default     = ""
}

variable "ip_address" {
  description = "Flexible IP to reuse (already in the DNS); empty: a new one is created."
  type        = string
  default     = ""
}

variable "zone" {
  description = "Scaleway zone."
  type        = string
  default     = "fr-par-1"
}

variable "instance_type" {
  description = "Scaleway instance type: the smallest is enough."
  type        = string
  default     = "STARDUST1-S"
}

variable "image" {
  description = "Scaleway image label (check with: scw marketplace image list)."
  type        = string
  default     = "rockylinux_10"
}

variable "root_volume_gb" {
  type    = number
  default = 10
}

variable "caddy_image" {
  type    = string
  default = "docker.io/library/caddy:2"
}
