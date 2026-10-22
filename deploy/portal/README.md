# Client portal: reporting database and Grafana (Terraform, Scaleway)

One instance holds the reporting database (PostgreSQL, TLS) and Grafana behind Caddy (HTTPS,
Let's Encrypt). Terraform creates the instance, its public address and its security group;
cloud-init configures it at first boot (`cloud-init.yaml.tftpl`). Secrets are generated on the
instance and never pass through Terraform, its state, GitLab or a chat.

```
admin_ips ──22, 5432──▶ instance ◀──443── anyone (Caddy: 403 outside admin_ips)
                        ├─ PostgreSQL (TLS only; writer role for the A2VM jobs)
                        ├─ Grafana (reads PostgreSQL)
                        └─ Caddy (HTTPS, certificate from Let's Encrypt)
```

The Terraform part is specific to Scaleway; `cloud-init.yaml.tftpl` (Podman, Compose) is not, and
serves another provider's module (a client's private cloud) as it is.

## Deploy (from a workstation)

Prerequisites: Terraform ≥ 1.6 or OpenTofu, a Scaleway API key with rights on the project.

```bash
cd deploy/portal
cp terraform.tfvars.example terraform.tfvars     # domain, admin_ips (office, runner public address)
export SCW_ACCESS_KEY=… SCW_SECRET_KEY=… SCW_DEFAULT_PROJECT_ID=…
terraform init
terraform plan
terraform apply
```

Then, as `terraform output next_steps` says:

1. Create the DNS record `<domain> A <public_ip>` at your DNS provider (not managed here). To keep
   an address already in the DNS, set `ip_address`: Terraform attaches it and never deletes it.
2. Wait for the first boot: `ssh root@<public_ip> 'cloud-init status --wait'` (about 5 minutes).
   Logs: `/var/log/cloud-init-output.log`; containers: `podman ps` in `/opt/a2vm-portal`.
3. Read the writer password and the PostgreSQL certificate once, for the runner's CI/CD variables
   (masked, protected): `/opt/a2vm-portal/secrets/writer.txt`, `/opt/a2vm-portal/pg/server.crt`.
4. Grafana: `https://<domain>`, user `admin`, password in `/opt/a2vm-portal/secrets/grafana-admin.txt`.

The SSH keys of the Scaleway project are installed on the instance by Scaleway.

## Change, rebuild, remove

- `admin_ips`: `terraform apply` updates the security group in place. The Caddyfile and
  `pg_hba.conf` on the instance are written at first boot only: edit them there (then
  `podman-compose restart`), or rebuild.
- Rebuild (`terraform apply -replace=scaleway_instance_server.portal`) deletes the data volume:
  export the database first (`podman exec … pg_dump`), or let the next daily runs refill it.
- `terraform destroy` removes everything, data included.

## In GitLab CI (later)

GitLab CE stores the Terraform state (Operate > Terraform states, HTTP backend). A manual `plan`
then `apply` job on the code project, with the Scaleway key in masked variables, makes GitLab the
place the portal is deployed from, which is its role in production (HLD strategy D3, D14).

## Files in git, files out of git

In git: `*.tf`, `cloud-init.yaml.tftpl`, `terraform.tfvars.example`. Out of git (see
`.gitignore`): `terraform.tfvars`, `*.tfstate*`, `.terraform/`.
