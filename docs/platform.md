# The platform with OpenTofu (v0.25.0, HLD D22)

From Linux machines reached by SSH, one `tofu apply` deploys what the platform needs outside the
tenant projects: the Kubernetes cluster and what it runs for every tenant, the collectors near the
networks and, as an option, the identity provider. The tenants themselves are still deployed by
their pipelines (`deploy-k8s`, `docs/kubernetes.md`).

```
operator's machine ── tofu apply ── SSH ──▶ servers k8s01..03 (RKE2)   ── addons, portal, Keycloak (option)
  deploy/tofu/<root>                     ├─▶ agents (RKE2)
  terraform.tfvars, secret files         ├─▶ collectors (Podman, one timer per connector)
  state in GitLab                        └─▶ Keycloak VM (option: Podman, PostgreSQL, Caddy)
GitLab ── tenant project ── deploy-k8s ── GitLab agent ──▶ namespace ngvm-<tenant>
```

| Root (`deploy/tofu/`) | Machines |
| --- | --- |
| `existing` | Machines that exist: an inventory of addresses (§3) |
| `scaleway` | Instances created on Scaleway, then the platform on them (§8) |
| `azure` | VMs created on Azure, then the platform on them (§8) |
| `libvirt` | VMs created on a bare KVM host (Rocky Linux 10, libvirt), then the platform on them (§8) |

Every root calls `modules/platform`: the same steps on the same kinds of machines, however they
were made.

## 1. What OpenTofu needs

- **OpenTofu** 1.6 or later on the operator's machine (`brew install opentofu`, or the package of
  the distribution). Terraform 1.6 or later runs the same files; the documentation and the CI use
  OpenTofu (MPL 2.0; Terraform has been under the BSL since 2023).
- **The machines**: Ubuntu 22.04 or 24.04, Rocky Linux 9 or 10. SSH with a key, as root or as a
  user with passwordless sudo (`sudo -n`). Each machine reaches the internet directly or through the
  proxy of `network` (packages, RKE2, images, charts); see §4 for a registry mirror.
- **`ssh`** on the operator's machine (the kubeconfig and the secrets of Keycloak come back by SSH).

What a step does on a machine is a script of `deploy/tofu/scripts`, run as root: OpenTofu copies
it with the files of the step into `/tmp/ngvm-tofu-<step>` (mode 700), runs it and removes the
folder. A script only changes what differs, so an apply can be run again at any time. A step runs
again when its settings, the scripts or `revision` change.

## 2. State and secrets

- **State in GitLab** (the HTTP backend; it is encrypted and kept with the project). Each root has a
  `backend "http" {}`; with a personal access token (scope `api`) read from where it is stored:

```bash
cd deploy/tofu/existing
export TF_HTTP_PASSWORD="$(security find-generic-password -s gitlab-tofu -w)"
tofu init -backend-config="address=https://gitlab.example.org/api/v4/projects/<id>/terraform/state/platform" \
  -backend-config="lock_address=https://gitlab.example.org/api/v4/projects/<id>/terraform/state/platform/lock" \
  -backend-config="unlock_address=https://gitlab.example.org/api/v4/projects/<id>/terraform/state/platform/lock" \
  -backend-config="username=<user>" -backend-config="lock_method=POST" -backend-config="unlock_method=DELETE"
```

  A local state, for a test only: a file `backend_override.tf` with `terraform { backend "local" {} }`
  (ignored by Git).
- **No secret is a variable.** A secret is a file on the operator's machine, named by its path in
  `terraform.tfvars` (`token_file`, `password_file`…). OpenTofu reads it at apply time only: it is
  copied into a folder of mode 700 under `secrets_dir` (`~/.ngvm/secrets/stage/<step>`), uploaded,
  installed with mode 600 and removed; neither its content nor a hash of it is in the state. As
  OpenTofu does not see a change in such a file, change `revision` to push it again.
- **Made where they are used**: the passwords of Keycloak on a VM (its database, its bootstrap
  admin) are made on that VM, in `/etc/ngvm/keycloak` (root only), and never leave it.
- **Coming back**: the secret of each client Keycloak makes comes back as
  `~/.ngvm/secrets/keycloak/<client>.secret` (mode 600); the portal's is used by the apply itself.
  Give the others to their CI/CD variable, then delete the file.
- **`terraform.tfvars`** holds addresses and paths, no secret; it stays out of Git (`.gitignore`).
  Keep it in a private project of its own, or next to the state.

Files to make once (the paths are those of the examples):

```bash
mkdir -p -m 700 ~/.ngvm/secrets
openssl rand -hex 32 > ~/.ngvm/secrets/rke2-token
chmod 600 ~/.ngvm/secrets/rke2-token
```

The cluster's token must never change once the cluster exists (the nodes join with it).

## 3. Machines that exist (`deploy/tofu/existing`)

```bash
cd deploy/tofu/existing
cp terraform.tfvars.example terraform.tfvars
tofu init -backend-config=…
tofu plan
tofu apply
```

`hosts` lists the machines by name, their SSH address and user, and their roles:

| Role | What the machine runs |
| --- | --- |
| `server` | An RKE2 server (control plane and etcd, and the workloads). 1 or 3; never two on the same `physical_host` |
| `agent` | An RKE2 agent (workloads only) |
| `collector` | One or more collectors (`collectors`, §6) |
| `keycloak` | Keycloak, when `keycloak.mode = "vm"` (§7) |

A machine can have several roles (a server that is also a collector, in a lab). `internal_address`
is the address of the cluster's traffic when it differs from the SSH address (a cloud's private
network); `ssh.bastion` reaches machines that are not reached directly.

Why 1 or 3 servers: etcd needs a majority. Two servers stop when one is lost, as a single one does,
with twice the machines. Three servers on two physical machines stop when the machine that holds
two of them stops (the homelab, 13 to 14 November): `physical_host` lets OpenTofu refuse that.

## 4. The cluster (RKE2)

- RKE2 from `install_url` (`https://get.rke2.io`), the latest of `rke2_channel` or exactly
  `rke2_version`; the first server, then the second and the third one after the other, then the
  agents. On Rocky Linux, SELinux stays enforcing (`selinux: true`, the RPM of RKE2).
- `ingress`: `ingress-nginx` (RKE2's default, the charts' default `controller: nginx`) or `traefik`.
- `cis = true`: the CIS profile of RKE2 (the etcd user, the kernel settings).
- `disable_firewall = true` (default): firewalld or ufw stopped, as RKE2 asks; the network policies
  of the charts filter inside the cluster, the site's firewall outside it.
- **Proxy** (`network.http_proxy`, `https_proxy`, `no_proxy`): for the packages, RKE2 and its
  containerd (`/etc/default/rke2-server`, with the cluster's own ranges in `NO_PROXY`), Helm and the
  pulls of Podman.
- **CAs** (`network.ca_files`): in the system's trust store of every machine.
- **Registry mirrors** (`network.registry_mirrors`) and registry CAs (`network.registry_ca_files`):
  in `/etc/rancher/rke2/registries.yaml` and `/etc/containers/certs.d` (Podman).
- `kubeconfig_file`: the administrator's kubeconfig, written on the operator's machine (mode 600)
  with the API on the first server's address (in its certificate with `tls_san`).

## 5. In the cluster

From the first server, once every node is up:

| Addon | Setting | What |
| --- | --- | --- |
| Helm | `helm_version` | On the first server, its checksum verified |
| StorageClass | `storage` | `local-path` (the provisioner of Rancher, default class): volumes on the node's disk, lost with the node. `none`: bring your own (Longhorn, a SAN driver) |
| cert-manager | `cert_manager` | With its CRDs; a ClusterIssuer `issuer_name` when `issuer` is `ca` (the platform's CA, `issuer_ca_cert_file` and `issuer_ca_key_file`) or `acme` (Let's Encrypt, names reachable from the internet) |
| CloudNativePG | `cnpg` | The operator of the tenants' databases and of the portal's (`deploy/cnpg/README.md`) |
| GitLab agent | `gitlab_agent` | The agent `deploy-k8s` goes through: its token (`token_file`, from *Operate > Kubernetes clusters* of the agent's project), GitLab's CA |
| Portal | `portal` | The chart `ngvm-portal` of this release, with `values_file` (`docs/reporting.md`), the pull secret of `registry` and the secret of its OIDC client |

The tenants' namespaces, their Secrets and the chart `ngvm-tenant` stay with `deploy-k8s`: the
tenant project is still where a tenant is configured.

## 6. Collectors

Each entry of `collectors` is one collector (`docs/collectors.md`) on one host, run with Podman:

- `config_file`: its `collector.yaml`, written by hand as today; its `collector` and `tenant` must
  match the entry. The paths it names are under `/etc/ngvm/collector`.
- `files`: the files it names, by their name there (`token`, `ca.pem`, `targets.yaml`, a scan key,
  a SentinelOne token, the certificate and key of Cyberwatch), installed with mode 600 for the
  agent's user (10001). `gvm_env_file`: the GMP account of OpenVAS (root only, given to the container
  as its environment).
- `connectors`: connector → systemd `OnCalendar` (`"*-*-* 01:30:00"`). One timer per connector, with
  its own schedule; a connector removed from the list loses its timer. The poll (every 5 minutes)
  as before.
- `openvas_socket_dir`: the host folder that holds `gvmd.sock` when Greenbone runs on the same host
  (with Docker Compose: `/var/lib/docker/volumes/<project>_gvmd_socket_vol/_data`).
- `container_proxy`: `false` (default) runs the agent without the proxy (`--http-proxy=false`: a
  transparent proxy, or APIs reached directly); `true` gives it the platform's.
- `legacy_cleanup` (default `true`): the units of an A2VM collector (`a2vm-collector@…`, Docker) are
  stopped and removed. Docker and Greenbone are left as they are.
- The image is pulled with the deploy token of `registry`; a new image is a new `image` and an apply.

A collector installed by hand: `docs/collectors.md` §2 (the install script with Docker, or the
steps with Podman).

## 7. Keycloak

`keycloak.mode`:

- `none`: the organisation's identity provider. Nothing is installed; give its issuer to the
  portal's values and to the tenants (`NGVM_OIDC_ISSUER`), and the secret of the portal's client as
  `portal.oidc_client_secret_file`.
- `vm`: on the host of role `keycloak`, with Podman: PostgreSQL (a volume of its own), Keycloak
  listening on 127.0.0.1 only, and Caddy in front of it for HTTPS. `tls`: `files` (`tls_cert_file`,
  `tls_key_file`, the company's PKI), `acme` (Let's Encrypt, `acme_email`) or `internal` (Caddy's own
  CA, for a lab).
- `kubernetes`: in the cluster: the Keycloak operator, a CloudNativePG cluster for its database, a
  Keycloak and its Ingress (`cluster_issuer` or `tls_secret` for its certificate).

In both cases OpenTofu then makes the realm (`realm`, `ngvm`), the client scope `groups` (the claim
the portal and the chat read), the `groups` and the confidential clients of `clients` (client id →
redirect URIs: the portal `https://<host>/login/generic_oauth`, a tenant's chat
`https://<chat host>/oauth/oidc/callback`). Their secrets come back as files (§2); the portal's goes
into its Secret `portal-portal-oidc`. Users and their groups are managed in Keycloak, or come from a
directory federated there.

The bootstrap admin of Keycloak is a temporary account: make a permanent administrator in the
console, then remove it.

## 8. Machines created by OpenTofu

The three roots create the machines, then run the platform on them in the same apply; their
`platform` variable takes the settings of §3 to §7 (`ssh`, `network`, `cluster`, `addons`, `portal`,
`registry`, `collectors`, `keycloak`), and `collectors[*].host` names a machine. Their output
`hosts` is an inventory for `deploy/tofu/existing`.

| Root | Credentials (environment) | Network |
| --- | --- | --- |
| `scaleway` | `SCW_ACCESS_KEY`, `SCW_SECRET_KEY` | A private network for the cluster; SSH, the API, 80 and 443 open to `admin_cidrs`, 80 and 443 to `public_cidrs` |
| `azure` | `az login`, or `ARM_CLIENT_ID`, `ARM_CLIENT_SECRET`, `ARM_TENANT_ID` | A virtual network and its subnet; the same rules in its NSG. Rocky Linux: accept the marketplace terms once (`az vm image terms accept --publisher resf --offer rockylinux-x86_64 --plan 9-base`) |
| `libvirt` | The KVM host by SSH (`libvirt_uri`) | Static addresses by cloud-init, on a bridge (`bridge`) or a libvirt network (through the KVM host as `ssh.bastion`). Every VM on one physical host: one server |

Read the credentials from where they are stored, never from a file of the repository:

```bash
export SCW_ACCESS_KEY="$(security find-generic-password -s scw-access -w)"
export SCW_SECRET_KEY="$(security find-generic-password -s scw-secret -w)"
```

`tofu destroy` deletes the machines of these roots. On `existing`, it forgets the steps but leaves
the machines as they are.

## 9. From A2VM to NGVM (v0.25.0)

v0.25.0 renames the product: namespaces `ngvm-<tenant>`, Secrets and labels `ngvm.io/*`, schemas
`ngvm` and `ngvm_meta`, units `ngvm-collector@`, `/etc/ngvm`. A tenant moves by a new installation:

1. Optional, a backup of each tenant's database and of the portal's, while A2VM still runs (the
   commands are in the release notes, `CHANGELOG.md`, v0.25.0). A dump restored into the new
   database is renamed by `verdict db init` and the components' init (schemas `a2vm` and
   `a2vm_meta`); restore it with `--no-owner`.
2. The platform: this guide, or the cluster as it is.
3. Each tenant: CI/CD variables renamed `NGVM_*` (`docs/deployment.md`, *CI/CD variables renamed in
   v0.25.0*), `ref` and `NGVM_REF` at `v0.25.0`, include `project: vulnops/ngvm`, then `deploy-k8s`:
   the namespace `ngvm-<tenant>` starts empty and the next runs fill it.
4. The old namespaces (`a2vm-<tenant>`, `a2vm-via`, `a2vm-portal`) removed once the new ones run.
