# Ingesting trivy SBOMReports into guac

This repository contains a http server that can be used a backend for the [trivy-operator webhook reporter](https://aquasecurity.github.io/trivy-operator/v0.22.0/tutorials/integrations/webhook/).

# Get started local

1. Make sure to run a guac instance

```sh
git clone git@github.com:guacsec/guac.git
cd guac
make container start-service
 ```

2. Run trivy operator. See [link](https://github.com/aquasecurity/trivy-operator/blob/main/CONTRIBUTING.md#out-of-cluster) for instructions.
Set `OPERATOR_WEBHOOK_BROADCAST_URL=http://localhost:9999/report` when starting the trivy-operator \
Enable only sbom generation with the following env vars:

  ```
  OPERATOR_VULNERABILITY_SCANNER_ENABLED=false 
  OPERATOR_VULNERABILITY_SCANNER_SCAN_ONLY_CURRENT_REVISIONS=false
  OPERATOR_CONFIG_AUDIT_SCANNER_ENABLED=false
  OPERATOR_INFRA_ASSESSMENT_SCANNER_ENABLED=false
  OPERATOR_RBAC_ASSESSMENT_SCANNER_ENABLED=false
  OPERATOR_CONFIG_AUDIT_SCANNER_SCAN_ONLY_CURRENT_REVISIONS=false
  ```

> [!WARNING]
This project currently depends on a change in the trivy-operator: See <https://github.com/aquasecurity/trivy-operator/compare/main...hown3d:trivy-operator:vulnreport-purl>.
To develop against the fork, clone the trivy-operator fork into the same folder where this project resides and setup a go workspace:

```sh
go work init
go work use trivy-operator
go work use guac-trivy-operator-webhook
```

3. Start the api server
`make container start-in-guac`

# Testing

```sh
kubectl get sbomreports.aquasecurity.github.io -n $NAMESPACE $NAME -o json | curl -v -X POST --data-binary @- localhost:9999/report
```
