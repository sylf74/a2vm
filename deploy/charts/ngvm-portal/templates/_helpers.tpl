{{- define "ngvm-portal.name" -}}
{{- printf "%s-portal" .Release.Name -}}
{{- end -}}

{{- define "ngvm-portal.db" -}}
{{- printf "%s-portal-db" .Release.Name -}}
{{- end -}}

{{- define "ngvm-portal.labels" -}}
app.kubernetes.io/name: ngvm-portal
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{- define "ngvm-portal.selector" -}}
app.kubernetes.io/name: ngvm-portal
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* A password kept from one upgrade to the next: the value already in the Secret, else a new one. */}}
{{- define "ngvm-portal.keep" -}}
{{- $s := lookup "v1" "Secret" .root.Release.Namespace .secret -}}
{{- if and $s (index ($s.data | default dict) .key) -}}
{{- index $s.data .key | b64dec -}}
{{- else -}}
{{- randAlphaNum 32 -}}
{{- end -}}
{{- end -}}

{{/* Grafana's role from the groups of the sign-in: Admin, else Viewer, else refused (strict). */}}
{{- define "ngvm-portal.roles" -}}
{{- $claim := .groupsClaim | default "groups" -}}
{{- $parts := list -}}
{{- range .admins -}}
{{- $parts = append $parts (printf "contains(%s[*], '%s') && 'Admin'" $claim .) -}}
{{- end -}}
{{- range .viewers -}}
{{- $parts = append $parts (printf "contains(%s[*], '%s') && 'Viewer'" $claim .) -}}
{{- end -}}
{{- if not $parts -}}
{{- fail "grafana.oidc.enabled needs grafana.oidc.viewers or grafana.oidc.admins" -}}
{{- end -}}
{{- join " || " $parts -}}
{{- end -}}
