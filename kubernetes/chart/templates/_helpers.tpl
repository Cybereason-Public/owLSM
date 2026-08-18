{{/*
Stable identity labels. Used only as DaemonSet spec.selector.matchLabels.
*/}}
{{- define "owlsm.selectorLabels" -}}
app.kubernetes.io/name: owlsm
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: agent
{{- end }}

{{/*
Common labels: selector identity plus part-of, managed-by, and version.
*/}}
{{- define "owlsm.labels" -}}
{{ include "owlsm.selectorLabels" . }}
app.kubernetes.io/part-of: owlsm
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
