# Cloud scanner: Greenbone and the runner of the external project (Terraform, Scaleway)

One instance on the internet scans what a client exposes (`docs/openvas.md` §1, §5): Greenbone
Community Edition in containers, and the GitLab runner of the client's collection-only external
project (`<client>-external`, `docs/openvas.md` §6), whose `collect` job drives gvmd over its local
socket. Terraform creates the instance, its public address and its security group; cloud-init
configures it at first boot (`cloud-init.yaml.tftpl`). The instance is permanent and rebuilt the
same way when needed.

```
admin_ips ──22──▶ instance ──443──▶ GitLab (runner, jobs of the external project only)
                  ├─ Greenbone (gvmd, OpenVAS, feeds; GMP on a local socket, web UI on 127.0.0.1)
                  └─ GitLab Runner, Docker executor, the gvmd socket mounted in its jobs
                     │
                     └──▶ the client's public addresses (the scan)
```

Nothing is open inbound but SSH from `admin_ips`: GMP never leaves the instance, the runner
connects out. Secrets stay on the instance or never reach Terraform:

| Secret | Where it comes from | Where it lives |
| --- | --- | --- |
| GMP password of the account `vulnops` (role User) | Generated at first boot | `/opt/a2vm-scanner/secrets/gvm-password.txt`; given to the jobs by the runner (`environment` of `config.toml`), never stored in GitLab |
| Password of the Greenbone web interface's `admin` | Generated at first boot | `/opt/a2vm-scanner/secrets/gvm-admin.txt` |
| Runner authentication token (`glrt-…`) | GitLab, when the runner is created | Sent on the standard input of `register-runner.sh` over SSH; then `/etc/gitlab-runner/config.toml` |
| Client certificate for a reverse proxy in front of GitLab (optional) | Your own CA | Copied over SSH to `/opt/a2vm-scanner/certs/` |

Scan only addresses the client owns and has agreed to have scanned; check that the provider's
terms allow it (`docs/openvas.md` §1).

## Deploy (from a workstation)

Prerequisites: Terraform ≥ 1.6 or OpenTofu, a Scaleway API key with rights on the project.

```bash
cd deploy/scanner
cp terraform.tfvars.example terraform.tfvars     # admin_ips, gitlab_url; ip_address to keep an address
export SCW_ACCESS_KEY=… SCW_SECRET_KEY=… SCW_DEFAULT_PROJECT_ID=…
terraform init
terraform plan
terraform apply
```

Then, as `terraform output next_steps` says:

1. **First boot**: `ssh root@<public_ip> 'cloud-init status --wait'` (about 10 minutes). Logs:
   `/var/log/cloud-init-output.log`.
2. **Feeds**: the first synchronisation of the Greenbone feeds takes hours; a scan before it ends
   finds little. `ssh root@<public_ip> /opt/a2vm-scanner/status.sh` shows the containers, the
   number of NVTs loaded, the GMP accounts and the runner.
3. **Runner**: in the external project, **Settings > CI/CD > Runners > New project runner**, tag
   `scan-cloud` (`runner_tag`), "Run untagged jobs" off. With the
   [GitLab CLI](https://gitlab.com/gitlab-org/cli), the token goes from GitLab to the scanner
   without being shown:

   ```bash
   glab api --method POST user/runners -f runner_type=project_type \
     -f project_id="$(glab api 'projects/vulnops%2Fclients%2Flab-external' | jq .id)" \
     -f tag_list=scan-cloud -f description=a2vm-scanner | jq -r .token \
     | ssh root@<public_ip> /opt/a2vm-scanner/register-runner.sh
   ```

   From the web interface, copy the token shown once; read it without echo on the workstation
   (zsh; in bash, `read -rsp 'Runner token: ' T`), run this line on its own, then paste at the
   prompt and press Enter:

   ```bash
   read -rs 'T?Runner token: ' && echo && printf '%s\n' "$T" | ssh root@<public_ip> /opt/a2vm-scanner/register-runner.sh; unset T
   ```

   Pasted together with the lines that follow it, the prompt reads one of them instead of the
   token, and the script refuses it (`expected a runner authentication token`).

   If GitLab is reached through a reverse proxy that asks for a client certificate, copy it
   before registering (registering again later is fine: the previous registration is removed):

   ```bash
   scp scanner.crt root@<public_ip>:/opt/a2vm-scanner/certs/client.crt
   scp scanner.key root@<public_ip>:/opt/a2vm-scanner/certs/client.key
   ```

   `certs/ca.pem` is read too, when GitLab's certificate comes from a private CA (not needed
   with a public certificate, e.g. Let's Encrypt, on the reverse proxy).
4. **External project**: delete its CI/CD variables `A2VM_GVM_USER` and `A2VM_GVM_PASSWORD`, so
   that the runner's own apply; keep `A2VM_COLLECT_TAG` and `A2VM_RUNNER_TAG` equal to the tag.
   Its `targets.yaml` reads gvmd over the socket: `gmp: unix:///run/gvmd/gvmd.sock`.
5. **Check**: "Run pipeline" on the external project; the `collect` job log shows the scan's
   progress, then `ok   openvas [<hosts>]: <n> findings on <m> assets`.

The SSH keys of the Scaleway project are installed on the instance by Scaleway. The web interface
of Greenbone listens on the instance only: `ssh -L 9392:127.0.0.1:9392 root@<public_ip>`, then
`http://127.0.0.1:9392`, user `admin`.

## Operate

- **A token shown by mistake** (a terminal, a ticket): delete the runner in the external project
  (Settings > CI/CD > Runners), which revokes its token, create a new one and register again
  (step 3); the registration left on the instance is removed. The scripts never print the token:
  `status.sh` reads only the name and URL of the registration in `config.toml`.
- **While the feeds load**, gvmd holds its lock: `status.sh` gives each gvmd query 20 s and
  says "gvmd busy" rather than waiting.

- **Feeds**: a systemd timer (`a2vm-greenbone-feed.timer`, `feed_update_time`, 03:30 UTC by
  default) pulls the newer feed and component images and restarts what changed. Keep it before the
  external project's schedule: a container restarted during a scan stops the scan. By hand:
  `ssh root@<public_ip> /opt/a2vm-scanner/feed-update.sh`.
- **Disk**: after the feeds, the same timer runs `cleanup.sh`: the stopped containers of the CI
  jobs, the images no container has used for 3 days, the runner's cache volumes no container uses,
  the system journal above 200 MB and the package cache. Greenbone's containers, images and volumes
  are never touched. `status.sh` shows the free space and warns under 15 %; by hand:
  `ssh root@<public_ip> /opt/a2vm-scanner/cleanup.sh`, then `docker system df` for what remains.
  The volume is 90 GB by default (`root_volume_gb`; 60 GB filled up with the jobs' images): raise
  it with `terraform apply` (in place), then on the instance `growpart` and `resize2fs` if the
  file system did not grow.
- **Logs**: `ssh root@<public_ip> 'cd /opt/a2vm-scanner/greenbone && docker compose -p greenbone-community-edition logs --tail 50 gvmd'`; the runner:
  `journalctl -u gitlab-runner`.
- **gvmd slow to answer**: raise `gmp_timeout_seconds` in the external project's `targets.yaml`
  (`docs/openvas.md` §4).
- **System updates**: Ubuntu's unattended upgrades are on (security fixes); a reboot restarts the
  containers and the runner.

## Change, rebuild, remove

- `admin_ips`, `root_volume_gb`: `terraform apply` updates the security group or the volume in
  place.
- **Scripts of a new release**: cloud-init runs at the first boot only, and `main.tf` ignores a
  changed template on a running instance (no replacement by mistake). Write the new scripts of
  `/opt/a2vm-scanner` and the feed service from the template, secrets and `scanner.env` kept:
  `python3 deploy/scanner/update-scripts.py | ssh root@<public_ip> bash`.
- `gitlab_url`, `feed_update_time`: written at first boot; edit `/opt/a2vm-scanner/scanner.env` or
  the timer there, or rebuild.
- **Rebuild** (`terraform apply -replace=scaleway_instance_server.scanner`): a new instance with new
  secrets; feeds synchronised again (hours), runner registered again (step 3). Keep the address
  with `ip_address`: the reverse proxy and the scanned hosts may filter on it. The scan history in
  gvmd is lost; A2VM's is not (the external project's jobs and the internal run keep it).
- `terraform destroy` removes the instance and its address when Terraform created it; delete the
  runner in the external project (Settings > CI/CD > Runners).

## Moving from a scanner installed by hand

1. `terraform apply` with `ip_address` set to the old scanner's address, after moving the address
   off the old instance (Scaleway console, Flexible IPs > Detach), or with a new address added to
   the reverse proxy's allow-list first.
2. Steps 1 to 5 above, then pause the old runner in the external project until a pipeline succeeds
   on the new one; then delete the old runner and the old instance.

## Files in git, files out of git

In git: `*.tf`, `cloud-init.yaml.tftpl`, `update-scripts.py`, `terraform.tfvars.example`. Out of git (see
`.gitignore`): `terraform.tfvars`, `*.tfstate*`, `.terraform/`.
