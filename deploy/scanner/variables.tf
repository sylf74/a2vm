# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
variable "name" {
  description = "Instance name (also its host name)."
  type        = string
  default     = "a2vm-scanner"
}

variable "admin_ips" {
  description = "Addresses (CIDR) allowed to SSH to the scanner (the office). Nothing else is open inbound: the runner connects out to GitLab, GMP stays on a local socket."
  type        = list(string)
  validation {
    condition     = length(var.admin_ips) > 0 && alltrue([for c in var.admin_ips : can(cidrhost(c, 0))])
    error_message = "admin_ips: at least one CIDR, e.g. 203.0.113.10/32."
  }
}

variable "gitlab_url" {
  description = "URL the runner reaches GitLab by, from the internet (e.g. the public name of a reverse proxy)."
  type        = string
  validation {
    condition     = can(regex("^https://", var.gitlab_url))
    error_message = "gitlab_url: an https:// URL."
  }
}

variable "runner_tag" {
  description = "Tag of the runner: the external project's A2VM_COLLECT_TAG and A2VM_RUNNER_TAG."
  type        = string
  default     = "scan-cloud"
}

variable "project_id" {
  description = "Scaleway project (Project settings > Project ID); empty: SCW_DEFAULT_PROJECT_ID."
  type        = string
  default     = ""
}

variable "ip_address" {
  description = "Flexible IP to reuse (the address the scanned hosts and the GitLab reverse proxy already know); empty: a new one is created. It is never deleted by terraform destroy when given here."
  type        = string
  default     = ""
}

variable "zone" {
  description = "Scaleway zone."
  type        = string
  default     = "fr-par-1"
}

variable "instance_type" {
  description = "Scaleway instance type: Greenbone needs at least 4 vCPU and 8 GB."
  type        = string
  default     = "PLAY2-MICRO"
}

variable "image" {
  description = "Scaleway image label (check with: scw marketplace image list). cloud-init.yaml.tftpl is written for Ubuntu 24.04."
  type        = string
  default     = "ubuntu_noble"
}

variable "root_volume_gb" {
  description = "System and data volume, GB: the Greenbone feeds and database take 20 GB and more, the CI jobs' images and caches the rest."
  type        = number
  default     = 90
}

variable "greenbone_compose_url" {
  description = "Compose file of the Greenbone Community Containers (official guide, greenbone.github.io/docs)."
  type        = string
  default     = "https://greenbone.github.io/docs/latest/_static/compose.yaml"
}

variable "feed_update_time" {
  description = "Daily time (UTC, systemd OnCalendar) the Greenbone feed images are pulled again; before the external project's schedule."
  type        = string
  default     = "*-*-* 03:30:00"
}
