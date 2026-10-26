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

{{/* Checks of the values that templates cannot express alone. */}}
{{- define "a2vm-tenant.checks" -}}
{{- if not (has .Values.collect.mode (list "local" "intake")) -}}
{{- fail "collect.mode must be local or intake" -}}
{{- end -}}
{{- if and (eq .Values.collect.mode "intake") (not .Values.intake.enabled) -}}
{{- fail "collect.mode intake needs intake.enabled (the detection service)" -}}
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
{{- range $var, $key := dict "LLM_API_KEY" "llm-api-key" "GTI_API_KEY" "gti-api-key" "A2VM_GVM_USER" "gvm-user" "A2VM_GVM_PASSWORD" "gvm-password" "A2VM_REPORTING_DSN" "reporting-dsn" "A2VM_GITLAB_TOKEN" "gitlab-token" }}
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
