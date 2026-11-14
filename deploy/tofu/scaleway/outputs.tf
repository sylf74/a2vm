# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
output "hosts" {
  description = "The instances as modules/platform reads them (an inventory for deploy/tofu/existing)."
  value       = local.hosts
}

output "platform" {
  description = "API server, kubeconfig, issuer, files of the clients' secrets, collectors."
  value = {
    api_server              = module.platform.api_server
    kubeconfig_file         = module.platform.kubeconfig_file
    keycloak_issuer         = module.platform.keycloak_issuer
    keycloak_client_secrets = module.platform.keycloak_client_secrets
    collectors              = module.platform.collectors
  }
}
