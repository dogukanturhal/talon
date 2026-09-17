{{/* templates/_helpers.tpl */}}

{{- define "talon.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "talon.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "talon.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "talon.labels" -}}
helm.sh/chart: {{ include "talon.chart" . }}
{{ include "talon.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: hexxlock-platform
app.kubernetes.io/component: identity-aware-proxy
hexxlock.com/environment: {{ .Values.global.environment | default "prod" }}
hexxlock.com/region: {{ .Values.global.region | default "eu-west-1" }}
{{- end -}}

{{- define "talon.selectorLabels" -}}
app.kubernetes.io/name: {{ include "talon.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "talon.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "talon.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
