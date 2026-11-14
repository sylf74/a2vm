# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
output "public_ip" {
  description = "The scanner's address: allow it on the GitLab reverse proxy, and on the scanned hosts if they filter."
  value       = local.ip_address
}

output "next_steps" {
  value = <<-EOT
    1. Wait for the first boot (about 10 minutes): ssh root@${local.ip_address} 'cloud-init status --wait'
    2. Feeds: the first synchronisation takes hours; follow it with
       ssh root@${local.ip_address} /opt/ngvm-scanner/status.sh
    3. Runner: create a project runner (tag ${var.runner_tag}) in the external project and send its
       token over SSH, as README.md shows; with a client certificate for the reverse proxy, copy it first.
    4. In the external project, delete the CI/CD variables NGVM_GVM_USER and NGVM_GVM_PASSWORD:
       the runner gives them to the jobs.
  EOT
}
