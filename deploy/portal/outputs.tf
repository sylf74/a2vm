# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
output "public_ip" {
  description = "Create the DNS record <domain> A <this address> at your DNS provider."
  value       = scaleway_instance_ip.portal.address
}

output "next_steps" {
  value = <<-EOT
    1. DNS: ${var.domain} A ${scaleway_instance_ip.portal.address}
    2. Wait for the first boot (about 5 minutes): ssh root@${scaleway_instance_ip.portal.address} 'cloud-init status --wait'
    3. Writer password and PostgreSQL certificate for the runner:
       ssh root@${scaleway_instance_ip.portal.address} 'cat /opt/a2vm-portal/secrets/writer.txt; cat /opt/a2vm-portal/pg/server.crt'
    4. Grafana: https://${var.domain} (admin password: /opt/a2vm-portal/secrets/grafana-admin.txt)
  EOT
}
