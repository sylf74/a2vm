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

The other variables are the pipeline's (`docs/deployment.md`): the job copies the secret ones
(`A2VM_SSH_KEY`, `LLM_API_KEY`, `GTI_API_KEY`, `A2VM_GVM_USER`, `A2VM_GVM_PASSWORD`,
`A2VM_REPORTING_DSN`, `A2VM_REPORTING_CA`, `A2VM_GITLAB_TOKEN`) into the Secret `a2vm-tenant` of the
namespace, never into the job log, and hands the others (`A2VM_LLM_*`, `A2VM_GTI_ENABLED`,
`A2VM_EXTERNAL_PROJECT`) to the CronJob. External detection uses the GitLab API with
`A2VM_GITLAB_TOKEN`, since a pod has no job token.

Then move the tenant's `.gitlab-ci.yml` to `v0.13.0` (both `ref` and `A2VM_REF`) and push: the
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
`publish`); a failed step stops the run and shows as `Init:Error`. Exit code 3 (partial
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

## 4. Limits of this step

- Watch and alert validation stay in GitLab pipelines.
- The run's report is read from the volume or the dashboards; there are no job artifacts.
- Without `collectors.yaml`, collection runs where the CronJob runs: the cluster must reach the
  targets (SSH, OpenVAS). With it (v0.13.0), collectors near the networks push and the cluster
  connects to no client machine (`collectors.md`).
- The detection service keeps its detections on a volume, one replica, until PostgreSQL (D15
  step 3); its read calls use a token of the daily run until service accounts.
- One namespace per tenant in a shared cluster; a client that requires a physical separation
  gets a cluster of its own, with the same chart (HLD D15, Tenant isolation).
