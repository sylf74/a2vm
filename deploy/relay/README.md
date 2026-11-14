# Relay of the public sources (v0.23.4)

Topology R of [`docs/hld/proposals/intel-placement.md`](../../docs/hld/proposals/intel-placement.md):
everything stays on premises (the radar, the shared service, the LLM, the data), and the requests to
the public sources go through one small cloud instance. For the corporate proxy it is ordinary HTTPS
to one domain; the instance reaches only the hosts listed.

```
https://relay.example.org/www.cisa.gov/<path>               -> https://www.cisa.gov/<path>
https://relay.example.org/raw.githubusercontent.com/<path>  -> https://raw.githubusercontent.com/<path>
```

- **Not a forward proxy, not a tunnel**: no CONNECT, no destination outside `hosts`, GET and HEAD only.
- **Its own token**: header `X-NGVM-Relay-Token`, generated on the instance, removed before the
  request goes upstream and from Caddy's log. Requests from outside `allowed_ips` get 403.
- **No credentials through it**: a request carrying `Authorization` or `X-Apikey` is refused (400).
  GTI, Microsoft Graph, Teams, the LLM go direct or through the corporate proxy. NGVM never sends
  them to the relay anyway.
- **Declared to the SOC** with the list of hosts (`terraform output next_steps`).

## Deploy (Scaleway)

```bash
cd deploy/relay
```

```bash
cp terraform.tfvars.example terraform.tfvars
```

Set `domain`, `allowed_ips` (the corporate egress addresses), `admin_ips`, then, with
`SCW_ACCESS_KEY` and `SCW_SECRET_KEY` in the environment:

```bash
terraform init && terraform apply
```

Create the DNS record shown, wait for the first boot, read the token
(`terraform output next_steps`).

## Tenants

CI/CD variables of the group of the tenants (or of a tenant):

| Variable | Value |
| --- | --- |
| `NGVM_RELAY_URL` | `https://relay.example.org` |
| `NGVM_RELAY_HOSTS` | the hosts of `hosts`, comma-separated (the output gives them) |
| `NGVM_RELAY_TOKEN` | the token, masked |
| `NGVM_HTTPS_PROXY` | when the relay itself is reached through the corporate proxy |

Kubernetes: `deploy-k8s` puts them into the tenant's Secret and values; GitLab mode: the jobs read
them from the environment. Then `via check-sources` shows the route of each source
(`[relay www.cisa.gov]`); a host not listed goes direct (`[direct …]`).

## Another host

Add it to `hosts` (and to `NGVM_RELAY_HOSTS`), then `terraform apply`: the instance is rebuilt with
the new Caddyfile and keeps its address when `ip_address` is set. Or edit
`/opt/ngvm-relay/Caddyfile` on the instance and `podman-compose restart` (lost at the next rebuild).
