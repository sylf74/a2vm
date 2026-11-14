# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
output "public_ip" {
  description = "Create the DNS record <domain> A <this address> at your DNS provider."
  value       = local.ip_address
}

output "next_steps" {
  value = <<-EOT
    1. DNS: ${var.domain} A ${local.ip_address}
    2. Wait for the first boot (about 5 minutes): ssh root@${local.ip_address} 'cloud-init status --wait'
    3. The relay's token, for the CI/CD variable NGVM_RELAY_TOKEN (masked):
       ssh root@${local.ip_address} 'cat /opt/ngvm-relay/secrets/relay-token'
    4. NGVM_RELAY_URL=https://${var.domain}  NGVM_RELAY_HOSTS=${join(",", var.hosts)}
  EOT
}
