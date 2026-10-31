# Tenants on Kubernetes (v0.12.0, HLD D15 steps 1 and 2)

The daily run of a tenant (collect → intelligence → detection → assets → triage → publish) can
run in a Kubernetes cluster instead of GitLab: a CronJob, one container per step in the image of
its pillar, on a working volume of its own. The code and the commands are the ones of the
pipeline; only the launcher changes. GitLab still holds the code, builds the images, keeps the
tenant's configuration and deploys it through the GitLab agent.

```
code project ── tag vX.Y.Z ──▶ images via, detect, verdict ──▶ GitLab registry
tenant project ── push ──▶ deploy-k8s ──(GitLab agent)──▶ namespace a2vm-<tenant>
                                                          ├── CronJob a2vm-<tenant>-daily
                                                          ├── ConfigMap (client.yaml, targets.yaml, settings.yaml)
                                                          ├── Secret a2vm-tenant (from the CI/CD variables)
                                                          ├── volume a2vm-<tenant>-data (work/, output/, cache)
                                                          └── with collectors.yaml (v0.13.0): Deployment,
                                                              Service, Ingress, NetworkPolicy a2vm-<tenant>-detect,
                                                              volume a2vm-<tenant>-detections, Secret a2vm-intake
collectors near the networks ── HTTPS push ──▶ ingress ──▶ a2vm-<tenant>-detect ◀── detect fetch (daily run)
```

Since v0.13.0, a tenant project with a `collectors.yaml` also gets its **detection service**: the
collectors near its networks push their detections there, and the daily run reads them instead
of collecting from the cluster (`collect.mode: intake`). Declaration, tokens, installation of a
collector and checks: [`collectors.md`](collectors.md).

What stays in GitLab in this step: the watch and the analysts' validation (`watch`,
`send-alerts`), which read the inventory of the daily **pipeline**. A tenant that uses the watch
keeps its daily schedule in GitLab until a later step moves the watch.

Host names below are examples.

## 1. Once per instance

1. **Container registry** on GitLab: the code project shows *Deploy > Container registry*. On an
   Omnibus instance, set `registry_external_url 'https://registry.example.org'` in
   `/etc/gitlab/gitlab.rb` and run `gitlab-ctl reconfigure`. Without a registry, the `images` job
   does not run.
2. **Images**: the tag `v0.12.1` (and every later tag) runs the `images` job of the code project:
   `<registry>/vulnops/a2vm/via`, `…/detect`, `…/verdict`, tagged like the release, built with
   Buildah on the build runner below.
3. **Pulling the images**: a group deploy token (group `vulnops` > *Settings > Repository >
   Deploy tokens*, scope `read_registry`), stored as group variables `A2VM_REGISTRY_USER`
   (visible) and `A2VM_REGISTRY_PASSWORD` (masked). The job turns them into a pull secret.
4. **Registry behind a private CA**: every node must trust it. On RKE2, on each node:

```bash
sudo cp registry-ca.crt /etc/rancher/rke2/registry-ca.crt
sudo tee /etc/rancher/rke2/registries.yaml >/dev/null <<'EOF'
configs:
  "registry.example.org":
    tls:
      ca_file: /etc/rancher/rke2/registry-ca.crt
EOF
sudo systemctl restart rke2-server
```

   (`rke2-agent` on a worker node.)
5. **Access to the cluster**: the GitLab agent's configuration (`.gitlab/agents/<agent>/config.yaml`
   in its project) lists the group of the tenants under `ci_access: groups`. If GitLab itself is
   behind a private CA, its CA as the group variable `A2VM_K8S_CA` (File): `kubectl` in the job
   reaches the cluster through GitLab.

### Build runner

The images are built on a runner of their own, never on the runner of the tenants' pipelines: an
image build needs more rights than a pipeline job, and the tenants' runner holds their scan keys.

- A small VM without client data (2 vCPU, 4 GB, 40 GB), with `git`, `buildah` and `gitlab-runner`;
  the CA of GitLab and of its registry in the system trust store (`update-ca-trust` on Rocky).
- A **project runner** of the code project only (*Settings > CI/CD > Runners > New project
  runner*), tag `build`, "Run untagged jobs" unchecked, **Protected** checked: only tags and
  protected branches use it, so only the code's maintainers run jobs there.
- **Shell executor**: Buildah runs rootless as the `gitlab-runner` user; no Docker daemon, no
  privileged container. The runner's package creates `gitlab-runner` as a system user, without
  the `/etc/subuid` and `/etc/subgid` ranges rootless Buildah needs: add them (a free range of
  65536 ids), otherwise the build stops on `potentially insufficient UIDs or GIDs`.

```bash
sudo dnf install -y git buildah
curl -L https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.rpm.sh | sudo bash
sudo dnf install -y gitlab-runner
sudo usermod --add-subuids 200000-265535 --add-subgids 200000-265535 gitlab-runner
sudo loginctl enable-linger gitlab-runner
grep gitlab-runner /etc/subuid /etc/subgid
sudo gitlab-runner register --non-interactive --url https://gitlab.example.org \
  --token "$(cat runner-token.txt)" --executor shell --description a2vm-build
```

The token (`glrt-…`) shown when the runner is created is read from a file, not typed; it is a
secret (`gitlab-runner list` prints it, `gitlab-runner verify` does not). A first
check: *Run pipeline* on `main`, then ▶ on `images` builds the images tagged with the commit.

## 2. Per tenant

CI/CD variables of the tenant project (or of a subgroup):

| Key | Value | Options |
| --- | --- | --- |
| `A2VM_K8S_CONTEXT` | The agent context, `<agent project path>:<agent name>`, e.g. `vulnops/k8s:homelab` | Visible |
| `A2VM_K8S_NAMESPACE` | Optional, default `a2vm-<project name>` | Visible |
| `A2VM_K8S_SCHEDULE` | Optional, cron in Europe/Paris, default `45 5 * * *` | Visible |
| `A2VM_IMAGE_REGISTRY` | Optional, default `<registry>/<code project path>` | Visible |
| `A2VM_VERDICT_SERVICE` | Optional, `false` to deploy no decision service (default `true`, v0.14.0) | Visible |
| `A2VM_RUN_MODE` | In the tenant's `.gitlab-ci.yml`: `gitlab` (default) or `kubernetes`, the daily run and the watch in the namespace only (§4) | — |
| `A2VM_CHAT_HOST` | Optional: the analysts' chat on the decision service, at this host (v0.15.0, `chat.md`) | Visible |
| `A2VM_DATABASE` | Optional, `true`: the tenant's PostgreSQL (CloudNativePG) for the watch, detection and decision services instead of their volumes (v0.18.0, §5) | Visible |
| `A2VM_DATABASE_SIZE`, `A2VM_DATABASE_STORAGE_CLASS`, `A2VM_DATABASE_INSTANCES` | Optional: the database's volume (default `5Gi`, the cluster's default class) and its instances (default `1`, `3` for a standby) | Visible |

The other variables are the pipeline's (`docs/deployment.md`): the job copies the secret ones
(`A2VM_SSH_KEY`, `LLM_API_KEY`, `GTI_API_KEY`, `A2VM_GVM_USER`, `A2VM_GVM_PASSWORD`,
`A2VM_REPORTING_DSN`, `A2VM_REPORTING_CA`, `A2VM_GITLAB_TOKEN`) into the Secret `a2vm-tenant` of the
namespace, never into the job log, and hands the others (`A2VM_LLM_*`, `A2VM_GTI_ENABLED`,
`A2VM_EXTERNAL_PROJECT`) to the CronJob. External detection uses the GitLab API with
`A2VM_GITLAB_TOKEN`, since a pod has no job token.

Then move the tenant's `.gitlab-ci.yml` to `v0.16.0` (both `ref` and `A2VM_REF`) and push: the
pipeline runs `validate`, then `deploy-k8s`, which ends with the CronJob and its volume. Each
later push to the default branch redeploys (new profile, new targets, new version).

## 3. Run, follow, compare

From a workstation with access to the cluster:

```bash
NS=a2vm-homelab
kubectl -n $NS create job --from=cronjob/a2vm-homelab-daily run-$(date +%H%M)
kubectl -n $NS get pods -w
kubectl -n $NS logs job/run-<HHMM> --all-containers --prefix -f
```

The steps run one after the other (`collect`, `via`, `detect`, `assets`, `triage`, then
`publish`, which pushes the run to the decision service, then to the reporting database); a failed step stops the run and shows as `Init:Error`. One run at a time: the CronJob forbids
overlaps, and since v0.13.3 a run started by hand while another holds the volume stops at `collect`. Exit code 3 (partial
collection, reporting database unreachable) is a warning, as in the pipeline.

The report and the reporting dataset are on the tenant's volume, in `output/<client>/`. To read
them, a short-lived pod mounts the volume while no run is going on:

```bash
kubectl -n $NS run reader --rm -i --restart=Never --image=busybox:1.37 \
  --overrides='{"spec":{"securityContext":{"runAsUser":10001,"fsGroup":10001},"volumes":[{"name":"d","persistentVolumeClaim":{"claimName":"a2vm-homelab-data"}}],"containers":[{"name":"reader","image":"busybox:1.37","command":["sh","-c","ls -R /data/output | head -50"],"volumeMounts":[{"name":"d","mountPath":"/data"}]}]}}'
```

Side by side with the pipeline, both runs publish to the reporting database (when
`A2VM_REPORTING_DSN` is set): one more run per day, the dashboards show the latest. Compare the
totals per level of the two runs of the same day (`runs` table, or the `overview` dashboard).
When they agree, switch off the tenant's daily schedule in GitLab (*Build > Pipeline schedules*),
except for a tenant that uses the watch (see above).

### Decision service (v0.14.0)

`deploy-k8s` deploys `verdict serve` next to the CronJob (Deployment, Service and volume
`a2vm-<tenant>-verdict`, `a2vm-<tenant>-runs`), unless `A2VM_VERDICT_SERVICE=false`. It makes two
tokens once and keeps them in the Secret `a2vm-tenant` (`verdict-publish-token`,
`verdict-read-token`), their digests in the Secret `a2vm-verdict`; none appears in the job log. The
`publish` step of each run pushes `triage.json`; the service keeps the last 7 runs (LLD triage
§15). Only the daily run and pods labelled `a2vm.io/verdict-reader=true` reach it. To read it
from a workstation (the token is mounted in the pod, never in its spec or a command line):

```bash
NS=a2vm-homelab
kubectl -n $NS logs deploy/a2vm-homelab-verdict --tail=5
kubectl -n $NS run verdict-reader --rm -i --restart=Never --image=curlimages/curl:8.11.1 \
  --labels=a2vm.io/verdict-reader=true \
  --overrides='{"spec":{"securityContext":{"runAsUser":10001},"volumes":[{"name":"t","secret":{"secretName":"a2vm-tenant","items":[{"key":"verdict-read-token","path":"token"}]}}],"containers":[{"name":"verdict-reader","image":"curlimages/curl:8.11.1","command":["sh","-c","curl -sf -H \"Authorization: Bearer $(cat /t/token)\" \"http://a2vm-homelab-verdict:8080/v1/tenants/homelab/decisions?level=ACT&limit=5\""],"volumeMounts":[{"name":"t","mountPath":"/t","readOnly":true}]}]}}'
```

### Analysts' chat (v0.15.0)

With `A2VM_CHAT_HOST`, `deploy-k8s` also deploys Open WebUI and the tool server `verdict tools` in
the namespace, on the tenant's LLM endpoints: `chat.md`. With `A2VM_OIDC_ISSUER` (v0.17.0) the
analysts sign in with the tenant's identity provider: `sign-in.md`.

## 4. The watch on Kubernetes (v0.16.0)

Set `A2VM_RUN_MODE: kubernetes` in the `variables:` of the tenant's `.gitlab-ci.yml` and push:
`deploy-k8s` then also deploys the watch service `via serve` and the watch CronJob, and the
scheduled pipelines of the project no longer run the daily jobs nor the watch (they can be switched
off). The watch's mail settings come from the same CI/CD variables as in GitLab (`A2VM_MAIL_FROM`,
`A2VM_SMTP_*` or `A2VM_GRAPH_*`, `A2VM_ANALYST_TO`); `contacts.yaml`, `watch-sources.yaml` and
`templates/alert*.docx` from the project. The first passage records the baseline (no alert), as a
first watch in GitLab.

```bash
NS=a2vm-homelab
kubectl -n $NS get deploy,cronjob -l 'app.kubernetes.io/component in (via,watch)'
kubectl -n $NS logs job/$(kubectl -n $NS get jobs -l app.kubernetes.io/component=watch --sort-by=.metadata.creationTimestamp -o name | tail -1 | cut -d/ -f2)
kubectl -n $NS logs deploy/a2vm-homelab-via --tail=20
```

Validation: the analysts' mail links to *Run pipeline* of the project with `A2VM_JOB=send` and the
alert's id filled in; running it is the validation. The job `send-alerts-k8s` starts a send Job in
the namespace and shows its log. Edited sheets: commit `edits/<alert id>.md` (or `.docx`) first,
as in GitLab. A PDF attachment needs the GitLab mode (LibreOffice is not in the via image).

With the analysts' sign-in and `A2VM_ALERTS_HOST` (v0.17.0, `docs/sign-in.md`), the mail links to
the review page instead: a validator corrects, validates or dismisses there, and the sender
(`a2vm-<tenant>-sender`) mails the validated alerts; GitLab then only deploys.

Back to GitLab: `A2VM_RUN_MODE: gitlab` and push; the watch's state stays in the service's volume
(`a2vm-<tenant>-watch`), the GitLab watch starts from its own cache.

## 5. The tenant's database (v0.18.0)

With `A2VM_DATABASE=true`, `deploy-k8s` gives the tenant a PostgreSQL cluster of its own in its
namespace, made and run by the CloudNativePG operator (`Cluster a2vm-<tenant>-db`), and the watch
service, the detection service and the decision service keep their data there instead of their
volumes. Each pillar creates its schema (`via`, `detect`, `verdict`) at start; every row carries the
tenant and row-level security keeps each transaction to its tenant. With their data in the database
the services have no volume of their own: they restart without a pause (rolling update) and can run
several replicas (`database.serviceReplicas`). The decision service also keeps the life of each
finding across runs (opened, closed, reopened, levels): `GET …/findings/closed` and the
`lifecycle` of a decision (LLD triage §15.8), and the chat's tool `list_closed_findings`.

```
namespace a2vm-<tenant>
  Cluster a2vm-<tenant>-db (CloudNativePG) ── database app, role app (no superuser)
    Secret a2vm-<tenant>-db-app  key uri ──▶ file /var/run/a2vm-db/uri   (A2VM_DB_DSN_FILE)
    Secret a2vm-<tenant>-db-ca   key ca.crt ─▶ file /var/run/a2vm-db-ca/ca.crt (A2VM_DB_CA, verify-full)
  via serve, detect serve, verdict serve ── 5432 ──▶ a2vm-<tenant>-db-rw   (NetworkPolicy both ways)
```

**Once per Kubernetes cluster**, install the operator (`deploy/cnpg/README.md`):

```bash
kubectl apply --server-side -f https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.29/releases/cnpg-1.29.3.yaml
kubectl rollout status deployment -n cnpg-system cnpg-controller-manager
```

**Per tenant**: set `A2VM_DATABASE=true` on the project and push. `deploy-k8s` checks that the
operator is there (the API group `postgresql.cnpg.io`), else it stops and says so. Then:

```bash
NS=a2vm-lab
kubectl -n $NS get cluster,pods -l cnpg.io/cluster=a2vm-lab-db
kubectl -n $NS logs deploy/a2vm-lab-verdict --tail=5
```

The services' first line says `store postgresql a2vm-lab-db-rw.a2vm-lab/app (TLS verified)`. The data
start empty: what the volumes held is not moved (the next daily run, watch passage and pushes of
the collectors fill the database). The old claims (`a2vm-<tenant>-watch`, `-detections`, `-runs`)
are kept by Helm; delete them by hand once the services run on the database. The cluster and its
volumes are kept by an uninstall too (resource policy `keep`).

Backups are the operator's (a `ScheduledBackup` to an object store, `deploy/cnpg/README.md`); A2VM
sets none in this version. Without `A2VM_DATABASE`, nothing changes: the volumes, one replica each.

## 6. Limits of this step

- With `A2VM_RUN_MODE=gitlab` (default) the watch and its validation stay in GitLab pipelines; with
  `kubernetes` the validation is started from a GitLab pipeline, or, with the analysts' sign-in
  and `A2VM_ALERTS_HOST` (v0.17.0), from the review page (`docs/sign-in.md`).
- The run's report is read from the volume, the dashboards or the decision service; there are no job artifacts.
- Without the tenant's database (§5), the decision service keeps the last runs as files, one
  replica; it is read with a token until service accounts and answers reads only (D15 step 3, read
  side).
- Without `collectors.yaml`, collection runs where the CronJob runs: the cluster must reach the
  targets (SSH, OpenVAS). With it (v0.13.0), collectors near the networks push and the cluster
  connects to no client machine (`collectors.md`).
- Without the tenant's database (§5), the detection service keeps its detections on a volume, one
  replica; its read calls use a token of the daily run until service accounts.
- One namespace per tenant in a shared cluster; a client that requires a physical separation
  gets a cluster of its own, with the same chart (HLD D15, Tenant isolation).
