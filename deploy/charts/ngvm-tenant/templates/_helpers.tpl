{{- define "ngvm-tenant.name" -}}
{{- printf "ngvm-%s" (required "tenant is required" .Values.tenant) -}}
{{- end -}}

{{- define "ngvm-tenant.labels" -}}
app.kubernetes.io/name: ngvm-tenant
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
ngvm/tenant: {{ .Values.tenant | quote }}
{{- end -}}

{{/* Labels that select the pods of one component: include "ngvm-tenant.selector" (dict "root" . "component" "detect") */}}
{{- define "ngvm-tenant.selector" -}}
app.kubernetes.io/name: ngvm-tenant
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Detection service of the tenant, inside the cluster. */}}
{{- define "ngvm-tenant.intakeUrl" -}}
{{- printf "http://%s-detect:8080" (include "ngvm-tenant.name" .) -}}
{{- end -}}

{{/* Ingress controller of the push endpoint: nginx, traefik or other (v0.13.0 values: nginx: false = other). */}}
{{- define "ngvm-tenant.ingressController" -}}
{{- $c := .Values.intake.ingress.controller | default "nginx" -}}
{{- if and (eq $c "nginx") (eq (toString .Values.intake.ingress.nginx) "false") -}}
{{- $c = "other" -}}
{{- end -}}
{{- $c -}}
{{- end -}}

{{/* Secret of the push endpoint's certificate. */}}
{{- define "ngvm-tenant.intakeTlsSecret" -}}
{{- if .Values.intake.ingress.tlsSecret -}}
{{- .Values.intake.ingress.tlsSecret -}}
{{- else if .Values.intake.ingress.clusterIssuer -}}
{{- printf "%s-detect-tls" (include "ngvm-tenant.name" .) -}}
{{- end -}}
{{- end -}}

{{/* Decision service of the tenant, inside the cluster. */}}
{{- define "ngvm-tenant.verdictUrl" -}}
{{- printf "http://%s-verdict:8080" (include "ngvm-tenant.name" .) -}}
{{- end -}}

{{/* Tool server of the conversational search, inside the cluster. */}}
{{- define "ngvm-tenant.toolsUrl" -}}
{{- printf "http://%s-tools:8080" (include "ngvm-tenant.name" .) -}}
{{- end -}}

{{/* What the chat calls for its model: the endpoint itself, or the gateway when there are several. */}}
{{- define "ngvm-tenant.chatLlmUrl" -}}
{{- $eps := .Values.chat.llm.endpoints -}}
{{- if or (gt (len $eps) 1) .Values.chat.llm.clientCert -}}
{{- printf "http://%s-llm:8080%s" (include "ngvm-tenant.name" .) (urlParse (first $eps)).path | trimSuffix "/" -}}
{{- else -}}
{{- first $eps | trimSuffix "/" -}}
{{- end -}}
{{- end -}}

{{/* Dispatch service of the tenant, inside the cluster. */}}
{{- define "ngvm-tenant.dispatchUrl" -}}
{{- printf "http://%s-dispatch:8080" (include "ngvm-tenant.name" .) -}}
{{- end -}}

{{/* Watch service of the tenant, inside the cluster. */}}
{{- define "ngvm-tenant.viaUrl" -}}
{{- printf "http://%s-via:8080" (include "ngvm-tenant.name" .) -}}
{{- end -}}

{{/* A copy of the tenant's files where the watch reads them (the Word template beside the profile). */}}
{{- define "ngvm-tenant.watchFiles" -}}
mkdir -p /tmp/cfg/templates
cp /config/*.yaml /tmp/cfg/ 2>/dev/null || true
for t in /alert-template/alert*.docx; do if [ -s "$t" ]; then cp "$t" /tmp/cfg/templates/; fi; done
{{ include "ngvm-tenant.settings" . }}
SOURCES=/opt/ngvm/config/watch-sources.yaml
if [ -f /tmp/cfg/watch-sources.yaml ]; then SOURCES=/tmp/cfg/watch-sources.yaml; fi
if [ ! -s /secrets/via-run-token ]; then echo "No via-run-token: the watch service cannot be used"; exit 1; fi
{{- end -}}

{{/* Egress to the identity provider (oidc.egress, or the cluster's ingress controller). */}}
{{- define "ngvm-tenant.oidcEgress" -}}
{{- range .Values.oidc.egress }}
- to:
    - ipBlock:
        cidr: {{ .cidr | quote }}
  ports:
    - {port: {{ .port }}, protocol: TCP}
{{- end }}
{{- if .Values.oidc.inCluster }}
- to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: {{ .Values.chat.networkPolicy.ingressNamespace | quote }}
{{- end }}
{{- end -}}

{{/* Checks of the values that templates cannot express alone. */}}
{{- define "ngvm-tenant.checks" -}}
{{- if not (has .Values.collect.mode (list "local" "intake")) -}}
{{- fail "collect.mode must be local or intake" -}}
{{- end -}}
{{- if and (eq .Values.collect.mode "intake") (not .Values.intake.enabled) -}}
{{- fail "collect.mode intake needs intake.enabled (the detection service)" -}}
{{- end -}}
{{- if .Values.verdict.enabled -}}
{{- $_ := required "verdict.digestsSecret is required (Secret with the key digests)" .Values.verdict.digestsSecret -}}
{{- end -}}
{{- if .Values.intel.serve.enabled -}}
{{- $_ := required "intel.serve.digestsSecret is required (Secret with the key digests)" .Values.intel.serve.digestsSecret -}}
{{- end -}}
{{- if .Values.watch.enabled -}}
{{- $_ := required "watch.digestsSecret is required (Secret with the key digests)" .Values.watch.digestsSecret -}}
{{- if not .Values.secret.name -}}
{{- fail "watch.enabled needs secret.name (key via-run-token)" -}}
{{- end -}}
{{- end -}}
{{- if and .Values.watch.enabled .Values.watch.review.enabled -}}
{{- $_ := required "watch.review.host is required" .Values.watch.review.host -}}
{{- $_ := required "watch.review.enabled needs oidc.issuerUrl (the identity provider)" .Values.oidc.issuerUrl -}}
{{- $_ := required "oidc.clientId is required" .Values.oidc.clientId -}}
{{- if not .Values.oidc.validators -}}
{{- fail "watch.review.enabled needs oidc.validators (the groups that validate the alerts)" -}}
{{- end -}}
{{- end -}}
{{- if and .Values.oidc.issuerUrl (not .Values.oidc.inCluster) (not .Values.oidc.egress) -}}
{{- fail "oidc.issuerUrl needs oidc.egress (or oidc.inCluster) for the NetworkPolicies" -}}
{{- end -}}
{{- if .Values.dispatch.enabled -}}
{{- if not .Values.verdict.enabled -}}
{{- fail "dispatch.enabled needs verdict.enabled (the dispatch service reads the decision service)" -}}
{{- end -}}
{{- $_ := required "dispatch.digestsSecret is required (Secret with the key digests)" .Values.dispatch.digestsSecret -}}
{{- $_ := required "dispatch.enabled needs files.dispatch (--set-file files.dispatch=dispatch.yaml)" .Values.files.dispatch -}}
{{- if not .Values.secret.name -}}
{{- fail "dispatch.enabled needs secret.name (keys verdict-read-token, dispatch-run-token, dispatch-<target>)" -}}
{{- end -}}
{{- if .Values.dispatch.page.enabled -}}
{{- $_ := required "dispatch.page.host is required" .Values.dispatch.page.host -}}
{{- $_ := required "dispatch.page.enabled needs oidc.issuerUrl (the identity provider)" .Values.oidc.issuerUrl -}}
{{- if not .Values.dispatch.page.remediators -}}
{{- fail "dispatch.page.enabled needs dispatch.page.remediators (the groups that may ask for remediation)" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if .Values.chat.enabled -}}
{{- if not .Values.verdict.enabled -}}
{{- fail "chat.enabled needs verdict.enabled (the tools read the decision service)" -}}
{{- end -}}
{{- $_ := required "chat.host is required" .Values.chat.host -}}
{{- $_ := required "chat.toolsDigestsSecret is required (Secret with the key digests)" .Values.chat.toolsDigestsSecret -}}
{{- $_ := required "chat.llm.model is required (NGVM_LLM_MODEL)" .Values.chat.llm.model -}}
{{- if not .Values.chat.llm.endpoints -}}
{{- fail "chat.llm.endpoints is required: the tenant's approved LLM endpoints (NGVM_LLM_BASE_URL)" -}}
{{- end -}}
{{- if and .Values.chat.networkPolicy.enabled (not .Values.chat.llm.egress) -}}
{{- fail "chat.llm.egress is required with the NetworkPolicy: {cidr, port} of each LLM endpoint" -}}
{{- end -}}
{{- if not .Values.secret.name -}}
{{- fail "chat.enabled needs secret.name (keys chat-secret-key, chat-admin-password, chat-tools-token, verdict-read-token)" -}}
{{- end -}}
{{- if .Values.chat.llm.clientCert -}}
{{- if ne (len .Values.chat.llm.endpoints) 1 -}}
{{- fail "chat.llm.clientCert: one endpoint only (put several behind one https load balancer)" -}}
{{- end -}}
{{- if ne (urlParse (first .Values.chat.llm.endpoints)).scheme "https" -}}
{{- fail "chat.llm.clientCert: the endpoint must be https" -}}
{{- end -}}
{{- else if gt (len .Values.chat.llm.endpoints) 1 -}}
{{- $first := urlParse (first .Values.chat.llm.endpoints) -}}
{{- range .Values.chat.llm.endpoints -}}
{{- $u := urlParse . -}}
{{- if ne $u.scheme "http" -}}
{{- fail (printf "chat.llm.endpoints: %s: several endpoints go through the gateway, which reaches them over http only (put one https load balancer as the single endpoint instead)" .) -}}
{{- end -}}
{{- if ne $u.path $first.path -}}
{{- fail "chat.llm.endpoints: several endpoints must share their path (e.g. /v1)" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if not (has .Values.chat.ingress.controller (list "nginx" "traefik" "other")) -}}
{{- fail "chat.ingress.controller must be nginx, traefik or other" -}}
{{- end -}}
{{- end -}}
{{- if .Values.intake.enabled -}}
{{- $_ := required "intake.collectors is required (--set-file intake.collectors=collectors.yaml)" .Values.intake.collectors -}}
{{- $_ := required "intake.digestsSecret is required (Secret with the key digests)" .Values.intake.digestsSecret -}}
{{- if and (eq .Values.collect.mode "intake") (not .Values.secret.name) -}}
{{- fail "collect.mode intake needs secret.name (key detect-read-token)" -}}
{{- end -}}
{{- if and .Values.intake.ingress.enabled (not .Values.intake.ingress.host) -}}
{{- fail "intake.ingress.host is required with the ingress" -}}
{{- end -}}
{{- $controller := include "ngvm-tenant.ingressController" . -}}
{{- if not (has $controller (list "nginx" "traefik" "other")) -}}
{{- fail "intake.ingress.controller must be nginx, traefik or other" -}}
{{- end -}}
{{- if and .Values.intake.ingress.enabled (ne $controller "other") (not .Values.intake.ingress.allowFrom) -}}
{{- fail "intake.ingress.allowFrom is required: the addresses of the collectors, the only sources allowed to push" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Image of a pillar: include "ngvm-tenant.image" (dict "root" . "pillar" "via") */}}
{{- define "ngvm-tenant.image" -}}
{{- $root := .root -}}
{{- $tag := $root.Values.image.tag | default (printf "v%s" $root.Chart.AppVersion) -}}
{{- printf "%s/%s:%s" (required "image.registry is required" $root.Values.image.registry) .pillar $tag -}}
{{- end -}}

{{/* Environment shared by every step of the daily run: the cache on the data volume. */}}
{{- define "ngvm-tenant.env" -}}
- name: NGVM_CACHE_DIR
  value: /data/.cache
{{ include "ngvm-tenant.envCommon" . }}
{{- end -}}

{{/* The way out to the Internet (v0.23.4): the corporate proxy (HTTPS_PROXY, NO_PROXY), a CA bundle
(the system CAs and the proxy's, key ca-bundle of the tenant's Secret) and the relay of the public
sources (topology R; its token: key relay-token). Nothing when unset. */}}
{{- define "ngvm-tenant.outbound" -}}
{{- $p := .Values.proxy | default dict -}}
{{- $r := .Values.relay | default dict -}}
{{- if $p.https }}
{{- $no := concat (list ".svc" ".cluster.local" "localhost" "127.0.0.1") ($p.noProxy | default list) | uniq | join "," }}
{{- range $var := list "HTTPS_PROXY" "https_proxy" "HTTP_PROXY" "http_proxy" }}
- name: {{ $var }}
  value: {{ $p.https | quote }}
{{- end }}
{{- range $var := list "NO_PROXY" "no_proxy" }}
- name: {{ $var }}
  value: {{ $no | quote }}
{{- end }}
{{- end }}
{{- if and $p.ca $.Values.secret.name }}
- name: SSL_CERT_FILE
  value: /secrets/ca-bundle
- name: REQUESTS_CA_BUNDLE
  value: /secrets/ca-bundle
{{- end }}
{{- if $r.url }}
- name: NGVM_RELAY_URL
  value: {{ $r.url | quote }}
- name: NGVM_RELAY_HOSTS
  value: {{ join "," ($r.hosts | default list) | quote }}
- name: NGVM_RELAY_TOKEN_FILE
  value: /secrets/relay-token
{{- end }}
{{- end -}}

{{/* Whether a pod without the tenant's Secret mounted needs it for the way out (the intel pod). */}}
{{- define "ngvm-tenant.outboundSecrets" -}}
{{- $p := .Values.proxy | default dict -}}
{{- $r := .Values.relay | default dict -}}
{{- if and .Values.secret.name (or $p.ca $r.url) }}true{{ end -}}
{{- end -}}

{{/* Environment shared by every container, without NGVM_CACHE_DIR: each caller sets it once, since a
name given twice breaks the next "helm upgrade" that changes the list. */}}
{{- define "ngvm-tenant.envCommon" -}}
- name: NGVM_SINCE
  value: {{ .Values.daily.since | quote }}
- name: HOME
  value: /home/ngvm
{{- include "ngvm-tenant.outbound" . }}
{{- range $key, $value := .Values.env }}
- name: {{ $key }}
  value: {{ $value | quote }}
{{- end }}
{{- if .Values.intel.url }}
- name: NGVM_INTEL_URL
  value: {{ .Values.intel.url | quote }}
- name: NGVM_INTEL_TOKEN_FILE
  value: /secrets/intel-token
- name: NGVM_INTEL_RADAR_TOKEN_FILE
  value: /secrets/intel-radar-token
{{- end }}
{{- if .Values.secret.name }}
- name: NGVM_TEAMS_WEBHOOK_FILE
  value: /secrets/teams-webhook
{{- end }}
{{- if .Values.secret.name }}
# An LLM behind mutual TLS (v0.23.14): keys llm-client-cert, llm-client-key and llm-ca of the
# Secret; a key absent, its file is missing and the client does without.
- name: NGVM_LLM_CLIENT_CERT_FILE
  value: /secrets/llm-client-cert
- name: NGVM_LLM_CLIENT_KEY_FILE
  value: /secrets/llm-client-key
- name: NGVM_LLM_CA_FILE
  value: /secrets/llm-ca
{{- end }}
{{- if .Values.secret.name }}
{{- range $var, $key := dict "LLM_API_KEY" "llm-api-key" "GTI_API_KEY" "gti-api-key" "NGVM_GVM_USER" "gvm-user" "NGVM_GVM_PASSWORD" "gvm-password" "NGVM_REPORTING_DSN" "reporting-dsn" "NGVM_GITLAB_TOKEN" "gitlab-token" "NGVM_SMTP_PASSWORD" "smtp-password" "NGVM_GRAPH_CLIENT_SECRET" "graph-client-secret" }}
- name: {{ $var }}
  valueFrom:
    secretKeyRef:
      name: {{ $.Values.secret.name }}
      key: {{ $key }}
      optional: true
{{- end }}
{{- end }}
{{- end -}}

{{/* Mounts shared by every step. */}}
{{- define "ngvm-tenant.mounts" -}}
- name: data
  mountPath: /data
- name: config
  mountPath: /config
  readOnly: true
- name: home
  mountPath: /home/ngvm
- name: tmp
  mountPath: /tmp
{{- if .Values.secret.name }}
- name: secrets
  mountPath: /secrets
  readOnly: true
{{- end }}
{{- if .Values.intake.enabled }}
- name: collectors
  mountPath: /intake
  readOnly: true
{{- end }}
{{- end -}}

{{/* Resolves the settings file, as the pipeline does. */}}
{{- define "ngvm-tenant.settings" -}}
SETTINGS=/opt/ngvm/config/settings.yaml
if [ -f /config/settings.yaml ]; then SETTINGS=/config/settings.yaml; fi
# The LLM's answers kept on the working volume from one run to the next (v0.23.7).
export NGVM_LLM_CACHE_FILE="${NGVM_LLM_CACHE_FILE:-/data/llm-cache.json}"
{{- end -}}

{{/* The tenant's PostgreSQL cluster (CloudNativePG, v0.18.0): its name, and what a service needs to
reach it: the connection string (the cluster's secret <db>-app, key uri) and the cluster's CA
(secret <db>-ca, key ca.crt only), as files; egress to its pods and the DNS. */}}
{{- define "ngvm-tenant.dbName" -}}
{{- printf "%s-db" (include "ngvm-tenant.name" .) -}}
{{- end -}}

{{- define "ngvm-tenant.dbEnv" -}}
{{- if .Values.database.enabled }}
- name: NGVM_DB_DSN_FILE
  value: /var/run/ngvm-db/uri
- name: NGVM_DB_CA
  value: /var/run/ngvm-db-ca/ca.crt
{{- end }}
{{- end -}}

{{- define "ngvm-tenant.dbMounts" -}}
{{- if .Values.database.enabled }}
- name: db
  mountPath: /var/run/ngvm-db
  readOnly: true
- name: db-ca
  mountPath: /var/run/ngvm-db-ca
  readOnly: true
{{- end }}
{{- end -}}

{{- define "ngvm-tenant.dbVolumes" -}}
{{- if .Values.database.enabled }}
- name: db
  secret:
    secretName: {{ include "ngvm-tenant.dbName" . }}-app
    defaultMode: 0440
    items:
      - {key: uri, path: uri}
- name: db-ca
  secret:
    secretName: {{ include "ngvm-tenant.dbName" . }}-ca
    defaultMode: 0440
    items:
      - {key: ca.crt, path: ca.crt}
{{- end }}
{{- end -}}

{{- define "ngvm-tenant.dbEgress" -}}
{{- if .Values.database.enabled }}
- to:
    - podSelector:
        matchLabels:
          cnpg.io/cluster: {{ include "ngvm-tenant.dbName" . }}
  ports:
    - {port: 5432, protocol: TCP}
- to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: {{ .Values.database.dnsNamespace | quote }}
  ports:
    - {port: 53, protocol: UDP}
    - {port: 53, protocol: TCP}
{{- end }}
{{- end -}}
