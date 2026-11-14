# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
terraform {
  required_version = ">= 1.6"
  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "~> 0.8.3"
    }
  }
  # The state in GitLab (docs/platform.md §2).
  backend "http" {}
}

# The KVM host, reached by SSH (its key from the SSH agent or keyfile= in the URI).
provider "libvirt" {
  uri = var.libvirt_uri
}
