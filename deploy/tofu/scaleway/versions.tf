# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
terraform {
  required_version = ">= 1.6"
  required_providers {
    scaleway = {
      source  = "scaleway/scaleway"
      version = "~> 2.50"
    }
  }
  # The state in GitLab (docs/platform.md §2).
  backend "http" {}
}

# Credentials from the environment: SCW_ACCESS_KEY, SCW_SECRET_KEY (never in a file of the
# repository). The project: var.project_id, else SCW_DEFAULT_PROJECT_ID.
provider "scaleway" {
  zone       = var.zone
  region     = substr(var.zone, 0, length(var.zone) - 2)
  project_id = var.project_id == "" ? null : var.project_id
}
