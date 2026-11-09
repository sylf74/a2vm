# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
output "public_ip" {
  description = "Create the DNS record <domain> A <this address> at your DNS provider."
  value       = local.ip_address
}

output "next_steps" {
  value = <<-EOT
    1. DNS: ${var.domain} A ${local.ip_address}
    2. Wait for the first boot (about 5 minutes): ssh root@${local.ip_address} 'cloud-init status --wait'
    3. The relay's token, for the CI/CD variable A2VM_RELAY_TOKEN (masked):
       ssh root@${local.ip_address} 'cat /opt/a2vm-relay/secrets/relay-token'
    4. A2VM_RELAY_URL=https://${var.domain}  A2VM_RELAY_HOSTS=${join(",", var.hosts)}
  EOT
}
