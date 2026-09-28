{{- define "tg.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tg.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "tg.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tg.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "tg.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "tg.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: telveguard
{{- end -}}

{{- define "tg.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "tg.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "tg.secretName" -}}
{{- default (include "tg.fullname" .) .Values.existingSecret -}}
{{- end -}}

{{- define "tg.policyConfigMap" -}}
{{- default (printf "%s-policy" (include "tg.fullname" .)) .Values.policy.existingConfigMap -}}
{{- end -}}

{{/* Secret'tan opsiyonel ortam değişkeni: anahtar yoksa pod yine başlar */}}
{{- define "tg.secretEnv" -}}
- name: {{ .env }}
  valueFrom:
    secretKeyRef:
      name: {{ .secret }}
      key: {{ .key }}
      optional: true
{{- end -}}
