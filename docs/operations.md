# Operator's manual (v0.18.1)

Day-to-day operation of a tenant deployed on Kubernetes (`A2VM_RUN_MODE: kubernetes`): where each
part runs, the usual actions, how to check the state, the known failures and their remedies,
upgrades. The installation of each part is in its own guide (table below); this manual does not
repeat it. The examples use the tenant `lab` (namespace `a2vm-lab`); replace it with yours.

| To install or change | Guide |
| --- | --- |
| GitLab groups, projects, variables, releases | [`deployment.md`](deployment.md) |
| The tenant on Kubernetes, the watch, the tenant's database | [`kubernetes.md`](kubernetes.md) |
| A collector near a network | [`collectors.md`](collectors.md) |
| SSH collection, OpenVAS, external scan | [`scanning.md`](scanning.md), [`openvas.md`](openvas.md) |
| Alerts, Word sheet, analysts' sign-in and review page | [`alerts.md`](alerts.md), [`alert-word.md`](alert-word.md), [`sign-in.md`](sign-in.md) |
| Chat, reporting database and Grafana, GTI | [`chat.md`](chat.md), [`reporting.md`](reporting.md), [`gti.md`](gti.md) |

## 1. Where each part runs

| Part | Where | When | Started by |
| --- | --- | --- | --- |
| Internal scans: SSH (Trivy, dnf) and OpenVAS | Collector VM near the network (`a2vm-collector@<connector>`, Docker or Podman) | Its systemd timer (`install-collector.sh --schedule`, default 07:30) | systemd |
| External scan (OpenVAS from the internet) | Pipeline of the project `<tenant>-external`, on the runner of the cloud scanner (tag `scan-cloud`) | Its pipeline schedule | GitLab |
| Daily run: collect → via → detect → assets → triage → publish, inventory | CronJob `a2vm-<tenant>-daily` | `daily.schedule` (default 05:45, Europe/Paris) | Kubernetes |
| Watch | CronJob `a2vm-<tenant>-watch` | Every 10 minutes | Kubernetes |
| Detection, watch and decision services | Deployments `a2vm-<tenant>-detect`, `-via`, `-verdict` | Always | Kubernetes |
| Review page and sender | Deployments `a2vm-<tenant>-review` (oauth2-proxy), `-sender` | Always | Kubernetes |
| Chat | Deployments `a2vm-<tenant>-chat`, `-tools` | Always | Kubernetes |
| Tenant's database | CloudNativePG cluster `a2vm-<tenant>-db` (with `A2VM_DATABASE=true`) | Always | The operator |
| Reporting database and Grafana | The portal (`deploy/portal`) or a PostgreSQL of your own | Always | — |

**Order of the schedules.** The daily run reads the latest detection of each source, if it is not
older than the source's `max_age_hours` (30 by default). With the defaults the collectors push at
07:30 and the daily run starts at 05:45: each run takes the detections of the day before. For the
same day's, set the collector timers before the daily run, an OpenVAS scan early enough to end
before it (`sudo systemctl edit a2vm-collector@<connector>.timer`). The external scan likewise
runs before the daily run; one older than the profile's `external.max_age_days` is left out.

## 2. Usual actions

### Scan again, inside the network

On the collector VM:

```bash
systemctl list-timers 'a2vm-collector@*' --all
sudo systemctl start --no-block a2vm-collector@lan-ssh.service
sudo systemctl start --no-block a2vm-collector@lan-openvas.service
journalctl -fu a2vm-collector@lan-ssh.service
systemctl list-units 'a2vm-collector@*.service' --all
```

The connector names follow the `@` in the timer names. `--no-block` returns at once (an OpenVAS
scan can take hours); Ctrl-C leaves the journal without stopping the run. A finished run is
`inactive`; `failed` means read its journal (§4). Each detection accepted shows in the service:

```bash
kubectl -n a2vm-lab logs deploy/a2vm-lab-detect --tail=10
```

### Scan again, from the internet

In GitLab: project `<tenant>-external` > Build > Pipelines > Run pipeline on `main`. Its runner
must be online (Settings > CI/CD > Runners); a cloud scanner billed by the hour must be started
first. Nothing is started by hand on the scanner.

### Run the daily run now

```bash
kubectl -n a2vm-lab create job --from=cronjob/a2vm-lab-daily a2vm-lab-daily-manual-1101
kubectl -n a2vm-lab get pods -l job-name=a2vm-lab-daily-manual-1101 -w
kubectl -n a2vm-lab wait --for=condition=complete job/a2vm-lab-daily-manual-1101 --timeout=60m
```

The job name must be new (a date in it); delete an old job to reuse its name
(`kubectl -n a2vm-lab delete job <name>`). The steps run one after the other as init containers;
the pod ends `Completed`.

### Read the CronJobs, the jobs and the logs

```bash
kubectl -n a2vm-lab get cronjob
kubectl -n a2vm-lab describe cronjob a2vm-lab-daily
kubectl -n a2vm-lab get jobs --sort-by=.metadata.creationTimestamp
kubectl -n a2vm-lab logs job/a2vm-lab-daily-manual-1101 -c triage
kubectl -n a2vm-lab get pod <pod> -o jsonpath='{range .status.initContainerStatuses[*]}{.name}{" "}{.state.terminated.exitCode}{"\n"}{end}'
```

The last command gives the exit code of each step of a daily run: the first one not `0` is the one
to read (`-c <step>`). Exit code 3 is a warning (partial collection, a database unreachable): the
run goes on.

### The watch and its alerts

```bash
kubectl -n a2vm-lab logs job/$(kubectl -n a2vm-lab get jobs -l app.kubernetes.io/component=watch --sort-by=.metadata.creationTimestamp -o name | tail -1 | cut -d/ -f2)
kubectl -n a2vm-lab logs deploy/a2vm-lab-via --tail=20
kubectl -n a2vm-lab logs deploy/a2vm-lab-sender --tail=20
```

Analysts validate the alerts on the review page (`https://<A2VM_ALERTS_HOST>`); the sender mails
them within a minute.

## 3. Check the state

| Command | Expected |
| --- | --- |
| `kubectl -n a2vm-lab get pods` | Services `Running`; the last daily job `Completed`; watch jobs `Completed` every 10 minutes |
| `kubectl -n a2vm-lab get deploy -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.template.spec.containers[0].image}{"\n"}{end}'` | Every A2VM image at the tag of the tenant's `.gitlab-ci.yml` |
| `kubectl -n a2vm-lab logs deploy/a2vm-lab-verdict \| head -1` | `store postgresql … (TLS verified)` with the tenant's database, else `store files …`; then `latest run …` |
| `kubectl -n a2vm-lab logs deploy/a2vm-lab-via \| grep store` | The same for the watch service, with the number of alerts kept |
| `kubectl -n a2vm-lab get pods -l cnpg.io/cluster=a2vm-lab-db` | The database instance(s) `Running` |
| `kubectl -n a2vm-lab logs deploy/a2vm-lab-verdict --tail=5` | A `push tenant=lab run=… rows=…` line after each daily run |
| `helm -n a2vm-lab get values a2vm -o yaml` | What `deploy-k8s` set (database, chat, watch, sign-in) |

In the chat: "summary of the latest run" names the run and its date; "details of asset web01"
shows an asset, with its scans since v0.18.1, even when it has no finding.

## 4. Known failures and remedies

| Symptom | Cause | Remedy |
| --- | --- | --- |
| Daily run `Init:Error`, step `collect`: "no detection received from the collectors", each source "nothing received yet" | The detection service has nothing yet: a new database, collectors not run since, or their pushes refused | Run the connectors on the collector (§2), check the pushes in the detection service's log, then the daily run again |
| Step `collect`: "Another run holds the working volume" | A daily run is still running, or one was killed holding the lock | Wait for it; a lock older than the run's deadline (`daily.activeDeadlineSeconds`) is taken over by the next run |
| Step `collect`: a source "older than max_age_hours" | The collector did not push today (timer, scan failed) | Its journal on the collector; the run goes on with the other sources |
| Collector: `docker pull` or `podman pull` "HTTP Basic: Access denied" | The registry login of the VM has expired or its deploy token was revoked; or `docker login` used another user name than the token's | A new deploy token and a new login (§5, "Registry login of a collector") |
| Collector journal: push refused `401` or `403` | Token of the collector changed or not declared in `collectors.yaml` | `docs/collectors.md` (declaration and tokens) |
| Watch: `inventory none yet` | The daily run has not pushed its inventory to the watch service (step `inventory`; needs `A2VM_RUN_MODE: kubernetes`) | The log of the step `inventory` of the last daily run; it warns and keeps the previous inventory when the service cannot be reached |
| Services restart two or three times after `A2VM_DATABASE=true` | They wait for the database's secret while the cluster initialises | None: they settle within two minutes |
| `deploy-k8s`: "the CloudNativePG operator is not installed" | `A2VM_DATABASE=true` without the operator | `deploy/cnpg/README.md` |
| `helm get values` shows no `database` although `A2VM_DATABASE` is set | The job did not see the variable: protected variable on an unprotected branch, wrong name or value | Settings > CI/CD > Variables: `A2VM_DATABASE` = `true`, then run the pipeline again |
| Step `publish`: "schema version 2 … run `verdict db init`" | The reporting database is older than the release | `verdict db init` once (`docs/reporting.md`) |
| The chat says "no run received yet" | The decision service has no run (new database) | A daily run (§2) |
| The chat does not find an asset | Before v0.18.1, an asset with no finding was not listed; since, an asset not scanned in the run | Since v0.18.1, check its scans in the remediation dashboard ("Assets by last scan") and the collector |
| A finding "gone without a new scan" (v0.18.1) | Its asset was not scanned again by the source that had seen it | The asset's scans (collector journal, targets); it is counted fixed only after a new scan |
| A French Grafana bar chart shows no bar (v0.17.3) | Dashboard imported before v0.18.1 | Import the French dashboards again |

## 5. Upgrades

### A2VM itself (the code project)

1. Push the release branch and open its merge request in one step:

   ```bash
   git push -o merge_request.create -o merge_request.target=main -o merge_request.title="Release X.Y.Z" origin release-X.Y.Z
   ```

2. When the merge request's pipeline is green, merge it in GitLab, then check what is on the
   server before tagging:

   ```bash
   git checkout main && git pull --ff-only origin main
   git show origin/main:deploy/charts/a2vm-tenant/Chart.yaml | grep -c X.Y.Z
   git tag vX.Y.Z origin/main && git push origin vX.Y.Z
   ```

   The count must be `2` (`version` and `appVersion`). The tag's pipeline builds the images.

### A tenant

When the tag's `images` job is green: in the tenant project, change `ref` and `A2VM_REF` in
`.gitlab-ci.yml` and push; `deploy-k8s` redeploys. Read the release's **Upgrade** paragraph in
`CHANGELOG.md` first: some releases need `verdict db init` on the reporting database, or a
dashboard imported again.

### Registry login of a collector

A collector pulls its image from the registry of the code project with a deploy token of its own,
read-only, that can be revoked without touching the cluster:

1. In GitLab, project `vulnops/a2vm` > Settings > Repository > Deploy tokens > Add token:
   name and **Username** `collector-<host>` (left empty, GitLab makes `gitlab+deploy-token-<n>`,
   shown in the list of tokens), an expiry date, scope **`read_registry` only** (no
   `read_repository`, no `write_registry`). GitLab shows the password once.
2. On the collector, log in with the token's **user name**, the password pasted at the prompt
   (not echoed, not kept in the shell history):

   ```bash
   read -rsp 'Deploy token password: ' T && echo && printf '%s' "$T" | sudo docker login registry.example.org:5050 -u collector-scan01 --password-stdin; unset T
   ```

   `Login Succeeded` is expected; Podman: `sudo podman login` with the same options. Still
   "Access denied": the user name is not the token's, the scope is not `read_registry`, or the
   token has expired (the list of deploy tokens shows all three).
3. Note the expiry date: the next pull after it fails the same way.

### A collector

```bash
sudo docker pull <registry>/vulnops/a2vm/detect:vX.Y.Z
sudo sed -i 's#/detect:v[0-9.]*#/detect:vX.Y.Z#' /etc/systemd/system/a2vm-collector@.service
sudo systemctl daemon-reload
```

The push contract (`detect.v1`) only grows: a collector of an older release still pushes, but
misses the fixes of the collection made since.

## 6. Stopping and starting the cluster

When the Kubernetes cluster is stopped for the night and started in the morning:

- The services, the database and the chat start again by themselves; the services may restart
  once while the database comes up.
- A schedule missed while the cluster was down: the daily run (no deadline) starts once when the
  cluster is back; the watch (`startingDeadlineSeconds` 300) skips what is older than 5 minutes and
  resumes at its next slot. Check with `kubectl -n a2vm-lab get jobs`; start the daily run by hand
  (§2) if none ran.
- The collectors and the external scan do not depend on the cluster: their pushes made while it
  was down are kept in the collector's spool and sent at the next run of the connector.
