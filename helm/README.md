# Helm Chart Documentation

This Helm chart deploys a microservices application on Kubernetes that allows to download logs from Pods.

## Install the chart:

```bash
helm install log-downloader --namespace log-downloader --create-namespace --values values.yaml .
```

## Configuration

The following table lists the configurable parameters of the chart and their default values.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Container image repository | `fra.ocir.io/fr2ylpr73ktd/demo/generic` |
| `image.tag` | Container image tag | `logdownloader` |
| `image.pullPolicy` | Container image pull policy | `IfNotPresent` |
| `image.pullSecrets` | List of image pull secrets | `[oracle]` |
| `watchAllNamespaces` | Watch all namespaces | `true` |
| `podLabels` | Labels to add to the pod | `app=configuratore,app=batch-ui,app=batchbase,app=cloudadmin,app=digitalsignature,app=eventsmanager,app=gotenberg,app=iamweb,app=notifier-ws,app=pecmanbase,app=pecmanfe,app=platform-arch,app=sck-configserver,app=solution,app=solution-base,app=solution-bpm` |
| `token` | Authentication token | `siav2025` |
| `ingress.host` | Ingress host | `log-downloader.siav-qa.dev` |
| `ingress.secretName` | Ingress secret name | `ssl-certificate-secret` |


