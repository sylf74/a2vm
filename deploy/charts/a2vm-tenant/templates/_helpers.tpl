{{- define "a2vm-tenant.name" -}}
{{- printf "a2vm-%s" (required "tenant is required" .Values.tenant) -}}
{{- end -}}

{{- define "a2vm-tenant.labels" -}}
app.kubernetes.io/name: a2vm-tenant
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
a2vm/tenant: {{ .Values.tenant | quote }}
{{- end -}}

{{/* Labels that select the pods of one component: include "a2vm-tenant.selector" (dict "root" . "component" "detect") */}}
{{- define "a2vm-tenant.selector" -}}
app.kubernetes.io/name: a2vm-tenant
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Detection service of the tenant, inside the cluster. */}}
{{- define "a2vm-tenant.intakeUrl" -}}
{{- printf "http://%s-detect:8080" (include "a2vm-tenant.name" .) -}}
{{- end -}}

{{/* Ingress controller of the push endpoint: nginx, traefik or other (v0.13.0 values: nginx: false = other). */}}
{{- define "a2vm-tenant.ingressController" -}}
{{- $c := .Values.intake.ingress.controller | default "nginx" -}}
{{- if and (eq $c "nginx") (eq (toString .Values.intake.ingress.nginx) "false") -}}
{{- $c = "other" -}}
{{- end -}}
{{- $c -}}
{{- end -}}

{{/* Secret of the push endpoint's certificate. */}}
{{- define "a2vm-tenant.intakeTlsSecret" -}}
{{- if .Values.intake.ingress.tlsSecret -}}
{{- .Values.intake.ingress.tlsSecret -}}
{{- else if .Values.intake.ingress.clusterIssuer -}}
{{- printf "%s-detect-tls" (include "a2vm-tenant.name" .) -}}
{{- end -}}
{{- end -}}

{{/* Decision service of the tenant, inside the cluster. */}}
{{- define "a2vm-tenant.verdictUrl" -}}
{{- printf "http://%s-verdict:8080" (include "a2vm-tenant.name" .) -}}
{{- end -}}

{{/* Tool server of the conversational search, inside the cluster. */}}
{{- define "a2vm-tenant.toolsUrl" -}}
{{- printf "http://%s-tools:8080" (include "a2vm-tenant.name" .) -}}
{{- end -}}

{{/* What the chat calls for its model: the endpoint itself, or the gateway when there are several. */}}
{{- define "a2vm-tenant.chatLlmUrl" -}}
{{- $eps := .Values.chat.llm.endpoints -}}
{{- if gt (len $eps) 1 -}}
{{- printf "http://%s-llm:8080%s" (include "a2vm-tenant.name" .) (urlParse (first $eps)).path | trimSuffix "/" -}}
{{- else -}}
{{- first $eps | trimSuffix "/" -}}
{{- end -}}
{{- end -}}

{{/* Watch service of the tenant, inside the cluster. */}}
{{- define "a2vm-tenant.viaUrl" -}}
{{- printf "http://%s-via:8080" (include "a2vm-tenant.name" .) -}}
{{- end -}}

{{/* A copy of the tenant's files where the watch reads them (the Word template beside the profile). */}}
{{- define "a2vm-tenant.watchFiles" -}}
mkdir -p /tmp/cfg/templates
cp /config/*.yaml /tmp/cfg/ 2>/dev/null || true
if [ -s /alert-template/alert.docx ]; then cp /alert-template/alert.docx /tmp/cfg/templates/alert.docx; fi
{{ include "a2vm-tenant.settings" . }}
SOURCES=/opt/a2vm/config/watch-sources.yaml
if [ -f /tmp/cfg/watch-sources.yaml ]; then SOURCES=/tmp/cfg/watch-sources.yaml; fi
if [ ! -s /secrets/via-run-token ]; then echo "No via-run-token: the watch service cannot be used"; exit 1; fi
{{- end -}}

{{/* Checks of the values that templates cannot express alone. */}}
{{- define "a2vm-tenant.checks" -}}
{{- if not (has .Values.collect.mode (list "local" "intake")) -}}
{{- fail "collect.mode must be local or intake" -}}
{{- end -}}
{{- if and (eq .Values.collect.mode "intake") (not .Values.intake.enabled) -}}
{{- fail "collect.mode intake needs intake.enabled (the detection service)" -}}
{{- end -}}
{{- if .Values.verdict.enabled -}}
{{- $_ := required "verdict.digestsSecret is required (Secret with the key digests)" .Values.verdict.digestsSecret -}}
{{- end -}}
{{- if .Values.watch.enabled -}}
{{- $_ := required "watch.digestsSecret is required (Secret with the key digests)" .Values.watch.digestsSecret -}}
{{- if not .Values.secret.name -}}
{{- fail "watch.enabled needs secret.name (key via-run-token)" -}}
{{- end -}}
{{- end -}}
{{- if .Values.chat.enabled -}}
{{- if not .Values.verdict.enabled -}}
{{- fail "chat.enabled needs verdict.enabled (the tools read the decision service)" -}}
{{- end -}}
{{- $_ := required "chat.host is required" .Values.chat.host -}}
{{- $_ := required "chat.toolsDigestsSecret is required (Secret with the key digests)" .Values.chat.toolsDigestsSecret -}}
{{- $_ := required "chat.llm.model is required (A2VM_LLM_MODEL)" .Values.chat.llm.model -}}
{{- if not .Values.chat.llm.endpoints -}}
{{- fail "chat.llm.endpoints is required: the tenant's approved LLM endpoints (A2VM_LLM_BASE_URL)" -}}
{{- end -}}
{{- if and .Values.chat.networkPolicy.enabled (not .Values.chat.llm.egress) -}}
{{- fail "chat.llm.egress is required with the NetworkPolicy: {cidr, port} of each LLM endpoint" -}}
{{- end -}}
{{- if not .Values.secret.name -}}
{{- fail "chat.enabled needs secret.name (keys chat-secret-key, chat-admin-password, chat-tools-token, verdict-read-token)" -}}
{{- end -}}
{{- if gt (len .Values.chat.llm.endpoints) 1 -}}
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
{{- $controller := include "a2vm-tenant.ingressController" . -}}
{{- if not (has $controller (list "nginx" "traefik" "other")) -}}
{{- fail "intake.ingress.controller must be nginx, traefik or other" -}}
{{- end -}}
{{- if and .Values.intake.ingress.enabled (ne $controller "other") (not .Values.intake.ingress.allowFrom) -}}
{{- fail "intake.ingress.allowFrom is required: the addresses of the collectors, the only sources allowed to push" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Image of a pillar: include "a2vm-tenant.image" (dict "root" . "pillar" "via") */}}
{{- define "a2vm-tenant.image" -}}
{{- $root := .root -}}
{{- $tag := $root.Values.image.tag | default (printf "v%s" $root.Chart.AppVersion) -}}
{{- printf "%s/%s:%s" (required "image.registry is required" $root.Values.image.registry) .pillar $tag -}}
{{- end -}}

{{/* Environment shared by every step. */}}
{{- define "a2vm-tenant.env" -}}
- name: A2VM_CACHE_DIR
  value: /data/.cache
- name: A2VM_SINCE
  value: {{ .Values.daily.since | quote }}
- name: HOME
  value: /home/a2vm
{{- range $key, $value := .Values.env }}
- name: {{ $key }}
  value: {{ $value | quote }}
{{- end }}
{{- if .Values.secret.name }}
{{- range $var, $key := dict "LLM_API_KEY" "llm-api-key" "GTI_API_KEY" "gti-api-key" "A2VM_GVM_USER" "gvm-user" "A2VM_GVM_PASSWORD" "gvm-password" "A2VM_REPORTING_DSN" "reporting-dsn" "A2VM_GITLAB_TOKEN" "gitlab-token" "A2VM_SMTP_PASSWORD" "smtp-password" "A2VM_GRAPH_CLIENT_SECRET" "graph-client-secret" }}
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
{{- define "a2vm-tenant.mounts" -}}
- name: data
  mountPath: /data
- name: config
  mountPath: /config
  readOnly: true
- name: home
  mountPath: /home/a2vm
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
{{- define "a2vm-tenant.settings" -}}
SETTINGS=/opt/a2vm/config/settings.yaml
if [ -f /config/settings.yaml ]; then SETTINGS=/config/settings.yaml; fi
{{- end -}}
