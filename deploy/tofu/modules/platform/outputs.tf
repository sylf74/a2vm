# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
output "api_server" {
  description = "Address of the Kubernetes API (the first server)."
  value       = local.first == "" ? null : "https://${var.hosts[local.first].address}:6443"
}

output "kubeconfig_file" {
  description = "The administrator's kubeconfig on the operator's machine, when fetched."
  value       = try(var.cluster.kubeconfig_file, "") == "" ? null : pathexpand(var.cluster.kubeconfig_file)
}

output "keycloak_issuer" {
  description = "Issuer of the realm (OIDC), when NGVM runs Keycloak."
  value       = var.keycloak.mode == "none" ? null : "https://${var.keycloak.hostname}/realms/${var.keycloak.realm}"
}

output "keycloak_client_secrets" {
  description = "Files of the clients' secrets on the operator's machine (mode 600): give each to the CI/CD variable or the values that need it, then delete it."
  value       = var.keycloak.mode == "none" ? {} : { for id in keys(var.keycloak.clients) : id => "${local.secrets_dir}/keycloak/${id}.secret" }
}

output "collectors" {
  description = "Collector -> host and connectors."
  value       = { for n, c in var.collectors : n => { host = c.host, connectors = keys(c.connectors) } }
}
