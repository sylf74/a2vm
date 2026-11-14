# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
  # The state in GitLab (docs/platform.md §2).
  backend "http" {}
}

# Credentials from the environment (ARM_CLIENT_ID, ARM_CLIENT_SECRET, ARM_TENANT_ID) or from
# `az login`; never in a file of the repository.
provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}
