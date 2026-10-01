# Kubernetes / OpenShift

Detección: YAML con `apiVersion` y `kind` ∈ {Deployment, StatefulSet, DaemonSet, Job, CronJob, Pod}; OpenShift: `DeploymentConfig`, `Route`.

- **securityContext:** `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem`, `capabilities.drop: [ALL]`, `seccompProfile`. En OpenShift las SCC del clúster pueden imponer UID: no es visible desde el manifiesto (limitación).
- **Riesgos:** `privileged: true`, `hostNetwork/hostPID/hostPath`, `latest` en imágenes, sin `resources.limits`.
- **Secretos:** objetos `Secret` con `data`/`stringData` en claro en el repositorio; credenciales en `env` en lugar de `secretKeyRef`.
- **Red/exposición:** `Service` tipo `LoadBalancer`/`NodePort` innecesario, `Route` sin TLS (`tls` ausente) en OpenShift, `NetworkPolicy` ausente.
- **Ambientes:** separación por namespace/overlay; sin endpoints o credenciales de producción en overlays de desarrollo.
