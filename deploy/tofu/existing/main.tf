# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# The platform on machines that already exist (docs/platform.md §3): copy
# terraform.tfvars.example to terraform.tfvars, fill it in, then tofu init and tofu apply.

module "platform" {
  source = "../modules/platform"

  hosts       = var.hosts
  ssh         = var.ssh
  network     = var.network
  cluster     = var.cluster
  addons      = var.addons
  portal      = var.portal
  registry    = var.registry
  collectors  = var.collectors
  keycloak    = var.keycloak
  secrets_dir = var.secrets_dir
  revision    = var.revision
}
