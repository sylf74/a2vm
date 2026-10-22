# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
output "public_ip" {
  description = "Create the DNS record <domain> A <this address> at your DNS provider."
  value       = local.ip_address
}

output "next_steps" {
  value = <<-EOT
    1. DNS: ${var.domain} A ${local.ip_address}
    2. Wait for the first boot (about 5 minutes): ssh root@${local.ip_address} 'cloud-init status --wait'
    3. Writer password and PostgreSQL certificate for the runner:
       ssh root@${local.ip_address} 'cat /opt/a2vm-portal/secrets/writer.txt; cat /opt/a2vm-portal/pg/server.crt'
    4. Grafana: https://${var.domain} (admin password: /opt/a2vm-portal/secrets/grafana-admin.txt)
  EOT
}
