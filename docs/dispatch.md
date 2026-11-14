# Remediation tickets (pillar 4, v0.20.0)

After each daily run, the tenant's dispatch service groups the decisions into remediation tickets,
one per asset and fix, and sends them to the ITSM of the teams that patch (iTop first). It follows
each ticket: it writes into it the vulnerabilities a scan confirmed fixed, resolves it when none is
left, and reopens it when it was closed while a scan still sees one. A person allowed to ask for
remediation can also send tickets from a dashboard: the link opens a page of NGVM, which shows
what will be sent and sends it only on confirmation (D18). Design: LLD dispatch-capitalization.

```
daily run ── publish ──► decision service ◄── reads ── dispatch service ──► iTop (UserRequest)
             dispatch ─────────────────────── POST runs ─┘     ▲
RSSI dashboard ── link "Remediate" ──► oauth2-proxy ──► page ───┘ (confirmation)
```

Needs: the tenant on Kubernetes with the decision service (`docs/kubernetes.md`), best with the
tenant's database (`NGVM_DATABASE=true`: the findings closed by a scan come from it, and the tickets
are kept there); for the page, the analysts' sign-in (`docs/sign-in.md`).

## 1. iTop

1. **A Person the tickets come from**: Configuration management > Contacts > New Person, name
   `NGVM` (first name `NGVM`), organisation: the tenant's. It is the `caller` of `dispatch.yaml`.
   NGVM looks for it in that organisation (`caller_organization` for another one); when two
   persons of the organisation carry that name, give its e-mail as `caller` (v0.23.3).
2. **Optionally a Team** the tickets are given to (e.g. `Linux`), in the same organisation: the
   `team` of `dispatch.yaml`.
3. **An account for NGVM**, distinct from the read-only CMDB account (`docs/cmdb.md`): Administration
   tools > User accounts > New iTop user, login `ngvm-itsm`, contact the Person above, profiles
   **REST Services User** and **Support Agent** (creates and updates user requests), allowed
   organisation: the tenant's. Its password is made where it is stored, the tenant project's
   variable (§2), and pasted once into iTop:

   ```bash
   openssl rand -base64 24
   ```

4. Check from a machine that reaches iTop, the password read from a file you just wrote, not typed
   on the command line:

   ```bash
   curl -sS https://itop.lab.example/webservices/rest.php?version=1.3 -d auth_user=ngvm-itsm --data-urlencode auth_pwd@itsm-password.txt --data-urlencode 'json_data={"operation":"core/get","class":"Person","key":"SELECT Person WHERE name = \"NGVM\"","output_fields":"name,org_name"}'
   ```

   `"code":0` and the Person are expected. Delete the file afterwards.

## 2. Tenant project

`dispatch.yaml` at the root of the project (example: `examples/lab/dispatch.yaml`, rules: LLD §4).
Start in `mode: dry-run`: the tickets are proposed and recorded, nothing reaches iTop; read them
(§4), then set `mode: live`.

When the client has priorities and an SLA (v0.21.0, `docs/sla.md`), a ticket carries the most urgent
priority of its findings in its title (`[NGVM ACT P1] …`) and its text, and its due date is the
earliest SLA due date of its findings (the BOD 26-04 one is shown beside it). By default iTop's
impact and urgency come from the level; a target may map them per priority, a priority not listed
keeping those of its level:

```yaml
targets:
  itsm:
    type: itop
    # ...
    priorities:
      P0: {impact: 1, urgency: 1}   # impact 1 a department, 2 a service, 3 a person
      P1: {impact: 2, urgency: 1}   # urgency 1 critical .. 4 low
```

A ticket already created keeps its impact and urgency; its findings, their priority and due date
are updated at each run.

Since v0.22.2 a target may name a date field of the ticket that receives NGVM's due date (the
client's SLA, else BOD 26-04): written on create and whenever it changes. iTop has none by default:
an extension adds it to `UserRequest` (for example `ngvm_due_date`, a date attribute):

```yaml
targets:
  itsm:
    type: itop
    # ...
    due_field: ngvm_due_date
```

When the team resolves a ticket in iTop, dispatch reads its `resolution_date` and keeps it as the
date declared for its findings (`GET fixes`); the reporting database counts it for the respect of
the SLA only when it lies between the last scan that still saw the flaw and the first that no longer
did (`docs/sla.md` §4). A ticket closed while a scan still sees the flaw is reopened, as before.

| Key | Value | Options |
| --- | --- | --- |
| `NGVM_DISPATCH_<TARGET>_PASSWORD` | Password of the account of a target of `dispatch.yaml`, `<TARGET>` its name in capitals, `-` as `_` (e.g. `NGVM_DISPATCH_ITSM_PASSWORD`) | Masked, protected |
| `NGVM_DISPATCH_<TARGET>_CA` | Optional: the CA of the target's certificate, when it is private | File |
| `NGVM_DISPATCH_EGRESS` | Optional: `cidr:port,...` of the targets, when the job cannot resolve their hosts | Visible |
| `NGVM_DISPATCH_IN_CLUSTER` | Optional, `true`: the targets are reached through the cluster's ingress controller | Visible |
| `NGVM_DISPATCH_HOST` | Host of the page of the requests for remediation (e.g. `dispatch-lab.apps.example.org`); needs the sign-in | Visible |
| `NGVM_OIDC_REMEDIATORS` | Groups that may ask for remediation, comma-separated (e.g. `NGVM-Remediation`) | Visible |
| `NGVM_DISPATCH_ALLOW` | Optional: the networks of those persons (CIDR) | Visible |
| `NGVM_DISPATCH_TLS_SECRET` | Optional; the ingress controller, class and issuer are the chat's | Visible |

The job `validate` checks `dispatch.yaml` (`dispatch check`); `deploy-k8s` deploys the service,
resolves the targets' hosts for its NetworkPolicy, makes its tokens and the key of the page once
(Secret `ngvm-tenant`), and copies each target's credential into the key `dispatch-<target>`; it
prints none. In Keycloak (`docs/sign-in.md` §1): the group of the remediators brought from the
directory, and `https://<NGVM_DISPATCH_HOST>/oauth2/callback` among the *Valid redirect URIs* and
its origin among the *Web origins* of the tenant's client.

## 3. Grafana

The dashboards `remediation`, `coverage` and `sla` (v0.21.0) have an RSSI version with the links "Remediate":

```bash
verdict grafana dashboard coverage --rssi > coverage.rssi.json
verdict grafana dashboard remediation --rssi --language fr > remediation.rssi.fr.json
```

(or the files `verdict/src/verdict/restitution/grafana/*.rssi*.json`). Import them in a folder whose
permissions give them to the persons who may ask for remediation; at import, Grafana asks the
address of the page: `https://<NGVM_DISPATCH_HOST>`. It is kept in the hidden constant `dispatch_url` of each
dashboard: when a link "Remediate" leads nowhere, set it in Edit > Settings > Variables >
`dispatch_url` > Value, then save the dashboard. The reading versions stay where they are: a
link gives no right, the page refuses anyone outside `NGVM_OIDC_REMEDIATORS`, but a reader has no
use for it.

## 4. Follow

```bash
kubectl -n ngvm-lab logs job/<daily job> -c dispatch
kubectl -n ngvm-lab logs deploy/ngvm-lab-dispatch --tail=20
```

The step prints `dispatch of run <id> (<mode>): proposed n, sent n, updated n, fixed n, claimed
fixed n, reopened n, errors n`. The service's first line gives its store, its mode, its targets, the
levels of the automatic tickets and the targets of the requests.

Since v0.23.19 the step also says what failed, grouped by message (`  61 x iTop refused: …`, the five
most frequent; the service's log has them too), and what a target says would stop its tickets, checked
once per run in live mode: for iTop, that `caller` is one Person of its organisation (`errors n;
iTop: 2 Persons with name 'NGVM' in 'Homelab': …`). The homelab sent no ticket for two days with
"errors 61" and nothing else.

The tickets and the requests, with the read token (`dispatch-read-token` of the Secret
`ngvm-tenant`), from a pod labelled `ngvm.io/dispatch-reader=true`. Since v0.22.2 `tickets` also
takes `since` and `until` (sent to the ITSM between two days), `limit` and `offset`, gives each
ticket its `sent_at` and the list its `counts` (by state, by level, with an ITSM number); the
analysts' chat asks it with `list_tickets`, through the tools' pod (labelled the same way):

```bash
kubectl -n ngvm-lab run dispatch-reader --rm -i --restart=Never --labels=ngvm.io/dispatch-reader=true --image=curlimages/curl:8.11.1 --overrides='{"spec":{"volumes":[{"name":"s","secret":{"secretName":"ngvm-tenant","items":[{"key":"dispatch-read-token","path":"t"}]}}],"containers":[{"name":"c","image":"curlimages/curl:8.11.1","command":["sh","-c","curl -s -H \"Authorization: Bearer $(cat /s/t)\" http://ngvm-lab-dispatch:8080/v1/tenants/lab/tickets?state=open"],"volumeMounts":[{"name":"s","mountPath":"/s"}]}]}}'
```

## 5. When something goes wrong

| Log or page | Cause | Remedy |
| --- | --- | --- |
| `iTop refused: code 1: ... Invalid login` | Wrong account or password | The account and `NGVM_DISPATCH_<TARGET>_PASSWORD`, then `deploy-k8s` |
| `iTop refused: code 100` (or 1) `... caller_id`, `org_id`, `team_id` | The Person, the organisation or the Team of `dispatch.yaml` does not exist in iTop under that name | The names in `dispatch.yaml` |
| `iTop refused: code 100: Error: caller_id: Several items found (2)`; since v0.23.19 also `iTop: 2 Persons with name … in …` | Two Persons carry the name of `caller` in the organisation (before v0.23.3: in any organisation) | Remove the duplicate in iTop, or give the Person's e-mail as `caller`; the tickets left `proposed` are sent by the next daily run, the requested ones too |
| `iTop refused: ... ev_resolve` | iTop does not allow resolving a request in its current status (e.g. never assigned) | Nothing: the ticket is fixed in NGVM; the team closes it in iTop |
| `iTop not reached` | Address, DNS, firewall, certificate | `NGVM_DISPATCH_<TARGET>_CA`, `NGVM_DISPATCH_EGRESS` |
| `decision service answered 404` | No run pushed yet | The next daily run |
| Page: "Your account may not ask for remediation" | Not in a group of `NGVM_OIDC_REMEDIATORS`, or the groups claim is missing | `docs/sign-in.md` §1 |
| Page: "A newer run arrived" | A run came between the page and the confirmation | Check the tickets again and confirm |
