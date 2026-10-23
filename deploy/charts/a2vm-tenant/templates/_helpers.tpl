{{- define "a2vm-tenant.name" -}}
{{- printf "a2vm-%s" (required "tenant is required" .Values.tenant) -}}
{{- end -}}

{{- define "a2vm-tenant.labels" -}}
app.kubernetes.io/name: a2vm-tenant
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
a2vm/tenant: {{ .Values.tenant | quote }}
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
{{- end -}}

{{/* Resolves the settings file, as the pipeline does. */}}
{{- define "a2vm-tenant.settings" -}}
SETTINGS=/opt/a2vm/config/settings.yaml
if [ -f /config/settings.yaml ]; then SETTINGS=/config/settings.yaml; fi
{{- end -}}
