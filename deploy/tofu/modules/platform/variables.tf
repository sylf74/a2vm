# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# The platform on machines that exist (docs/platform.md): only SSH is needed. No secret is a
# variable: a secret is a file on the operator's machine, named here by its path, copied to the
# machine that needs it at apply time, and never written to the state.

variable "hosts" {
  description = "The machines, by name. address: where OpenTofu reaches them by SSH. internal_address: the address of the cluster's traffic, when it is another one (a cloud's private network). roles: server (RKE2 server), agent (RKE2 agent), collector, keycloak. physical_host: the machine that runs a VM, so that two servers never share it."
  type = map(object({
    address          = string
    internal_address = optional(string, "")
    user             = optional(string, "root")
    port             = optional(number, 22)
    roles            = list(string)
    physical_host    = optional(string, "")
  }))
  validation {
    condition     = alltrue([for n, h in var.hosts : can(regex("^[a-z0-9][a-z0-9-]{0,62}$", n))])
    error_message = "hosts: names in lower-case letters, digits and dashes."
  }
  validation {
    condition     = alltrue(flatten([for h in var.hosts : [for r in h.roles : contains(["server", "agent", "collector", "keycloak"], r)]]))
    error_message = "hosts: roles are server, agent, collector or keycloak."
  }
  validation {
    condition     = contains([0, 1, 3], length([for h in var.hosts : h if contains(h.roles, "server")]))
    error_message = "hosts: 1 or 3 servers (etcd needs a majority: 2 servers do not survive the loss of one), or none."
  }
  validation {
    condition = (
      length([for h in var.hosts : h.physical_host if contains(h.roles, "server") && h.physical_host != ""]) ==
      length(distinct([for h in var.hosts : h.physical_host if contains(h.roles, "server") && h.physical_host != ""]))
    )
    error_message = "hosts: two servers on the same physical_host; one server per physical machine, or the loss of one machine stops the cluster."
  }
}

variable "ssh" {
  description = "How OpenTofu reaches the machines: a private key file (empty: the SSH agent), and a bastion when they are not reached directly."
  type = object({
    private_key_file = optional(string, "")
    bastion = optional(object({
      host = string
      user = optional(string, "root")
      port = optional(number, 22)
    }))
  })
  default = {}
}

variable "network" {
  description = "Proxy, CA and registry mirrors of the site. ca_files: CA certificates (PEM) every machine trusts (the company's, GitLab's, the registry's). registry_mirrors: registry -> mirror endpoints (RKE2). registry_ca_files: registry -> CA file, for RKE2 and Podman."
  type = object({
    http_proxy        = optional(string, "")
    https_proxy       = optional(string, "")
    no_proxy          = optional(list(string), [])
    ca_files          = optional(list(string), [])
    registry_mirrors  = optional(map(list(string)), {})
    registry_ca_files = optional(map(string), {})
  })
  default = {}
}

variable "cluster" {
  description = "The RKE2 cluster. token_file: the cluster's secret, made once (openssl rand -hex 32). kubeconfig_file: where the administrator's kubeconfig is written on the operator's machine (empty: not fetched)."
  type = object({
    token_file       = string
    rke2_version     = optional(string, "")
    rke2_channel     = optional(string, "stable")
    install_url      = optional(string, "https://get.rke2.io")
    ingress          = optional(string, "ingress-nginx")
    cis              = optional(bool, false)
    tls_san          = optional(list(string), [])
    cluster_cidr     = optional(string, "10.42.0.0/16")
    service_cidr     = optional(string, "10.43.0.0/16")
    disable_firewall = optional(bool, true)
    kubeconfig_file  = optional(string, "")
  })
  default = null
  validation {
    condition     = var.cluster == null || contains(["ingress-nginx", "traefik"], try(var.cluster.ingress, ""))
    error_message = "cluster.ingress: ingress-nginx or traefik."
  }
}

variable "addons" {
  description = "What the platform installs in the cluster. issuer: none, ca (issuer_ca_cert_file, issuer_ca_key_file) or acme (acme_email). gitlab_agent: the agent that deploys the tenants (deploy-k8s)."
  type = object({
    helm_version         = optional(string, "v3.19.0")
    helm_url             = optional(string, "https://get.helm.sh")
    storage              = optional(string, "local-path")
    local_path_url       = optional(string, "https://raw.githubusercontent.com/rancher/local-path-provisioner/v0.0.32/deploy/local-path-storage.yaml")
    cert_manager         = optional(bool, true)
    cert_manager_chart   = optional(string, "oci://quay.io/jetstack/charts/cert-manager")
    cert_manager_version = optional(string, "v1.19.1")
    issuer               = optional(string, "none")
    issuer_name          = optional(string, "ngvm")
    issuer_ca_cert_file  = optional(string, "")
    issuer_ca_key_file   = optional(string, "")
    acme_email           = optional(string, "")
    acme_server          = optional(string, "https://acme-v02.api.letsencrypt.org/directory")
    cnpg                 = optional(bool, true)
    cnpg_url             = optional(string, "https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.29/releases/cnpg-1.29.3.yaml")
    gitlab_agent = optional(object({
      name        = string
      kas_address = string
      token_file  = string
      ca_file     = optional(string, "")
      chart_repo  = optional(string, "https://charts.gitlab.io")
      version     = optional(string, "")
    }))
  })
  default = {}
  validation {
    condition     = contains(["none", "ca", "acme"], var.addons.issuer) && contains(["local-path", "none"], var.addons.storage)
    error_message = "addons.issuer: none, ca or acme; addons.storage: local-path or none."
  }
}

variable "portal" {
  description = "The portal (chart ngvm-portal) in the cluster. values_file: its values (docs/reporting.md). oidc_client_secret_file: the secret of its client at the identity provider; empty with keycloak.mode vm or kubernetes and a client portal_client: the one Keycloak made."
  type = object({
    enabled                 = optional(bool, false)
    namespace               = optional(string, "ngvm-portal")
    release                 = optional(string, "portal")
    values_file             = optional(string, "")
    oidc_client_secret_file = optional(string, "")
  })
  default = {}
}

variable "registry" {
  description = "Where the NGVM images are pulled from, and the files of a deploy token with read_registry (empty: no login)."
  type = object({
    host          = optional(string, "")
    user_file     = optional(string, "")
    password_file = optional(string, "")
  })
  default = {}
}

variable "collectors" {
  description = "Collectors, by name (the `collector:` of their collector.yaml). config_file: their collector.yaml; files: the files it names, by their name in /etc/ngvm/collector (token, ca.pem, targets.yaml, keys); connectors: connector -> systemd OnCalendar."
  type = map(object({
    host               = string
    tenant             = string
    image              = string
    config_file        = string
    files              = optional(map(string), {})
    gvm_env_file       = optional(string, "")
    connectors         = map(string)
    openvas_socket_dir = optional(string, "")
    container_proxy    = optional(bool, false)
    legacy_cleanup     = optional(bool, true)
  }))
  default = {}
  validation {
    condition     = alltrue([for n, c in var.collectors : can(regex("^[a-z0-9][a-z0-9-]{0,62}$", n)) && can(regex("^[a-z0-9][a-z0-9-]{0,62}$", c.tenant)) && length(c.connectors) > 0])
    error_message = "collectors: names and tenants in lower-case letters, digits and dashes; at least one connector each."
  }
}

variable "keycloak" {
  description = "The identity provider. mode: none (the organisation's, given by its issuer and client secrets), vm (on the host of role keycloak) or kubernetes (in the cluster). clients: client id -> redirect URIs. groups: made when missing."
  type = object({
    mode           = optional(string, "none")
    hostname       = optional(string, "")
    realm          = optional(string, "ngvm")
    clients        = optional(map(list(string)), {})
    groups         = optional(list(string), [])
    portal_client  = optional(string, "ngvm-portal")
    tls            = optional(string, "files")
    tls_cert_file  = optional(string, "")
    tls_key_file   = optional(string, "")
    acme_email     = optional(string, "")
    keycloak_image = optional(string, "quay.io/keycloak/keycloak:26.4")
    postgres_image = optional(string, "docker.io/library/postgres:17")
    caddy_image    = optional(string, "docker.io/library/caddy:2")
    operator_url   = optional(string, "https://raw.githubusercontent.com/keycloak/keycloak-k8s-resources/26.4.0/kubernetes")
    namespace      = optional(string, "keycloak")
    ingress_class  = optional(string, "nginx")
    cluster_issuer = optional(string, "")
    tls_secret     = optional(string, "")
    storage_size   = optional(string, "2Gi")
  })
  default = {}
  validation {
    condition     = contains(["none", "vm", "kubernetes"], var.keycloak.mode) && contains(["files", "acme", "internal"], var.keycloak.tls)
    error_message = "keycloak.mode: none, vm or kubernetes; keycloak.tls: files, acme or internal."
  }
}

variable "secrets_dir" {
  description = "Folder on the operator's machine where OpenTofu stages the secret files it copies, and writes the secrets Keycloak made (one file per client, mode 600). Outside any Git work tree."
  type        = string
  default     = "~/.ngvm/secrets"
}

variable "revision" {
  description = "Change it to run every step again (after a secret file changed, for instance): OpenTofu cannot see a change of a file it does not read."
  type        = string
  default     = "1"
}
