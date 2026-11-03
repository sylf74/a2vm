# Remediation tickets (pillar 4, v0.20.0)

After each daily run, the tenant's dispatch service groups the decisions into remediation tickets,
one per asset and fix, and sends them to the ITSM of the teams that patch (iTop first). It follows
each ticket: it writes into it the vulnerabilities a scan confirmed fixed, resolves it when none is
left, and reopens it when it was closed while a scan still sees one. A person allowed to ask for
remediation can also send tickets from a dashboard: the link opens a page of A2VM, which shows
what will be sent and sends it only on confirmation (D18). Design: LLD dispatch-capitalization.

```
daily run ── publish ──► decision service ◄── reads ── dispatch service ──► iTop (UserRequest)
             dispatch ─────────────────────── POST runs ─┘     ▲
RSSI dashboard ── link "Remediate" ──► oauth2-proxy ──► page ───┘ (confirmation)
```

Needs: the tenant on Kubernetes with the decision service (`docs/kubernetes.md`), best with the
tenant's database (`A2VM_DATABASE=true`: the findings closed by a scan come from it, and the tickets
are kept there); for the page, the analysts' sign-in (`docs/sign-in.md`).

## 1. iTop

1. **A Person the tickets come from**: Configuration management > Contacts > New Person, name
   `A2VM` (first name `A2VM`), organisation: the tenant's. It is the `caller` of `dispatch.yaml`.
2. **Optionally a Team** the tickets are given to (e.g. `Linux`), in the same organisation: the
   `team` of `dispatch.yaml`.
3. **An account for A2VM**, distinct from the read-only CMDB account (`docs/cmdb.md`): Administration
   tools > User accounts > New iTop user, login `a2vm-itsm`, contact the Person above, profiles
   **REST Services User** and **Support Agent** (creates and updates user requests), allowed
   organisation: the tenant's. Its password is made where it is stored, the tenant project's
   variable (§2), and pasted once into iTop:

   ```bash
   openssl rand -base64 24
   ```

4. Check from a machine that reaches iTop, the password read from a file you just wrote, not typed
   on the command line:

   ```bash
   curl -sS https://itop.lab.example/webservices/rest.php?version=1.3 -d auth_user=a2vm-itsm --data-urlencode auth_pwd@itsm-password.txt --data-urlencode 'json_data={"operation":"core/get","class":"Person","key":"SELECT Person WHERE name = \"A2VM\"","output_fields":"name,org_name"}'
   ```

   `"code":0` and the Person are expected. Delete the file afterwards.

## 2. Tenant project

`dispatch.yaml` at the root of the project (example: `examples/lab/dispatch.yaml`, rules: LLD §4).
Start in `mode: dry-run`: the tickets are proposed and recorded, nothing reaches iTop; read them
(§4), then set `mode: live`.

| Key | Value | Options |
| --- | --- | --- |
| `A2VM_DISPATCH_<TARGET>_PASSWORD` | Password of the account of a target of `dispatch.yaml`, `<TARGET>` its name in capitals, `-` as `_` (e.g. `A2VM_DISPATCH_ITSM_PASSWORD`) | Masked, protected |
| `A2VM_DISPATCH_<TARGET>_CA` | Optional: the CA of the target's certificate, when it is private | File |
| `A2VM_DISPATCH_EGRESS` | Optional: `cidr:port,...` of the targets, when the job cannot resolve their hosts | Visible |
| `A2VM_DISPATCH_IN_CLUSTER` | Optional, `true`: the targets are reached through the cluster's ingress controller | Visible |
| `A2VM_DISPATCH_HOST` | Host of the page of the requests for remediation (e.g. `dispatch-lab.apps.example.org`); needs the sign-in | Visible |
| `A2VM_OIDC_REMEDIATORS` | Groups that may ask for remediation, comma-separated (e.g. `A2VM-Remediation`) | Visible |
| `A2VM_DISPATCH_ALLOW` | Optional: the networks of those persons (CIDR) | Visible |
| `A2VM_DISPATCH_TLS_SECRET` | Optional; the ingress controller, class and issuer are the chat's | Visible |

The job `validate` checks `dispatch.yaml` (`dispatch check`); `deploy-k8s` deploys the service,
resolves the targets' hosts for its NetworkPolicy, makes its tokens and the key of the page once
(Secret `a2vm-tenant`), and copies each target's credential into the key `dispatch-<target>`; it
prints none. In Keycloak (`docs/sign-in.md` §1): the group of the remediators brought from the
directory, and `https://<A2VM_DISPATCH_HOST>/oauth2/callback` among the *Valid redirect URIs* and
its origin among the *Web origins* of the tenant's client.

## 3. Grafana

The dashboards `remediation` and `coverage` have an RSSI version with the links "Remediate":

```bash
verdict grafana dashboard coverage --rssi > coverage.rssi.json
verdict grafana dashboard remediation --rssi --language fr > remediation.rssi.fr.json
```

(or the files `verdict/src/verdict/restitution/grafana/*.rssi*.json`). Import them in a folder whose
permissions give them to the persons who may ask for remediation; at import, Grafana asks the
address of the page: `https://<A2VM_DISPATCH_HOST>`. The reading versions stay where they are: a
link gives no right, the page refuses anyone outside `A2VM_OIDC_REMEDIATORS`, but a reader has no
use for it.

## 4. Follow

```bash
kubectl -n a2vm-lab logs job/<daily job> -c dispatch
kubectl -n a2vm-lab logs deploy/a2vm-lab-dispatch --tail=20
```

The step prints `dispatch of run <id> (<mode>): proposed n, sent n, updated n, fixed n, claimed
fixed n, reopened n, errors n`. The service's first line gives its store, its mode, its targets, the
levels of the automatic tickets and the targets of the requests.

The tickets and the requests, with the read token (`dispatch-read-token` of the Secret
`a2vm-tenant`), from a pod labelled `a2vm.io/dispatch-reader=true`:

```bash
kubectl -n a2vm-lab run dispatch-reader --rm -i --restart=Never --labels=a2vm.io/dispatch-reader=true --image=curlimages/curl:8.11.1 --overrides='{"spec":{"volumes":[{"name":"s","secret":{"secretName":"a2vm-tenant","items":[{"key":"dispatch-read-token","path":"t"}]}}],"containers":[{"name":"c","image":"curlimages/curl:8.11.1","command":["sh","-c","curl -s -H \"Authorization: Bearer $(cat /s/t)\" http://a2vm-lab-dispatch:8080/v1/tenants/lab/tickets?state=open"],"volumeMounts":[{"name":"s","mountPath":"/s"}]}]}}'
```

## 5. When something goes wrong

| Log or page | Cause | Remedy |
| --- | --- | --- |
| `iTop refused: code 1: ... Invalid login` | Wrong account or password | The account and `A2VM_DISPATCH_<TARGET>_PASSWORD`, then `deploy-k8s` |
| `iTop refused: code 100` (or 1) `... caller_id`, `org_id`, `team_id` | The Person, the organisation or the Team of `dispatch.yaml` does not exist in iTop under that name | The names in `dispatch.yaml` |
| `iTop refused: ... ev_resolve` | iTop does not allow resolving a request in its current status (e.g. never assigned) | Nothing: the ticket is fixed in A2VM; the team closes it in iTop |
| `iTop not reached` | Address, DNS, firewall, certificate | `A2VM_DISPATCH_<TARGET>_CA`, `A2VM_DISPATCH_EGRESS` |
| `decision service answered 404` | No run pushed yet | The next daily run |
| Page: "Your account may not ask for remediation" | Not in a group of `A2VM_OIDC_REMEDIATORS`, or the groups claim is missing | `docs/sign-in.md` §1 |
| Page: "A newer run arrived" | A run came between the page and the confirmation | Check the tickets again and confirm |
