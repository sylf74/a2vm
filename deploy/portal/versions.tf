# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
terraform {
  required_version = ">= 1.6"
  required_providers {
    scaleway = {
      source  = "scaleway/scaleway"
      version = "~> 2.50"
    }
  }
  # State: local by default. In GitLab CI, use the GitLab-managed state (HTTP backend), see README.md.
}

# Credentials from the environment: SCW_ACCESS_KEY, SCW_SECRET_KEY, SCW_DEFAULT_PROJECT_ID.
provider "scaleway" {
  zone   = var.zone
  region = substr(var.zone, 0, length(var.zone) - 2)
}
