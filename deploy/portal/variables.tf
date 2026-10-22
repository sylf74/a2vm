# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
variable "name" {
  description = "Instance name (also its host name)."
  type        = string
  default     = "a2vm-portal"
}

variable "domain" {
  description = "Public DNS name of the portal (Grafana in HTTPS). The DNS record is created by hand; Let's Encrypt needs it before the first visit."
  type        = string
}

variable "admin_ips" {
  description = "Addresses (CIDR) allowed to SSH, to read Grafana and to write to PostgreSQL: the office, the runner's public address."
  type        = list(string)
  validation {
    condition     = length(var.admin_ips) > 0 && alltrue([for c in var.admin_ips : can(cidrhost(c, 0))])
    error_message = "admin_ips: at least one CIDR, e.g. 203.0.113.10/32."
  }
}

variable "project_id" {
  description = "Scaleway project (Project settings > Project ID); empty: SCW_DEFAULT_PROJECT_ID."
  type        = string
  default     = ""
}

variable "ip_address" {
  description = "Flexible IP to reuse (kept from an earlier instance, already in the DNS); empty: a new one is created. It is never deleted by terraform destroy when given here."
  type        = string
  default     = ""
}

variable "zone" {
  description = "Scaleway zone."
  type        = string
  default     = "fr-par-1"
}

variable "instance_type" {
  description = "Scaleway instance type: PostgreSQL and Grafana for a few tenants fit in 2 vCPU and 4 GB."
  type        = string
  default     = "PLAY2-NANO"
}

variable "image" {
  description = "Scaleway image label (check with: scw marketplace image list)."
  type        = string
  default     = "rockylinux_10"
}

variable "root_volume_gb" {
  description = "System and data volume, GB."
  type        = number
  default     = 20
}

variable "postgres_image" {
  type    = string
  default = "docker.io/library/postgres:17"
}

variable "grafana_image" {
  type    = string
  default = "docker.io/grafana/grafana-oss:11.5.0"
}

variable "caddy_image" {
  type    = string
  default = "docker.io/library/caddy:2"
}
