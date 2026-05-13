# CVE20251974IngressNightmareAssessment

> Assess Kubernetes clusters for CVE-2025-1974 (IngressNightmare) by detecting vulnerable
> ingress-nginx deployments and verifying if any valid remediation is in place.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![AppType](https://img.shields.io/badge/appType-httprequest-orange)
![Environment](https://img.shields.io/badge/environment-logical-green)
![ExecLevel](https://img.shields.io/badge/execlevel-app-purple)
![Severity](https://img.shields.io/badge/CVE--2025--1974-CVSS%209.8%20Critical-red)
![Last Updated](https://img.shields.io/badge/updated-2026--05--12-lightgrey)

---

## 📑 Table of Contents

1. [Overview](#overview)
2. [Rule Architecture](#rule-architecture)
3. [Inputs](#inputs)
4. [Tasks](#tasks)
5. [Outputs](#outputs)
6. [Configuration](#configuration)
7. [Usage Examples](#usage-examples)
8. [I/O Mapping](#io-mapping)
9. [Compliance Schema](#compliance-schema)
10. [Troubleshooting](#troubleshooting)
11. [Version History](#version-history)
12. [References](#references)

---

## 1. Overview

### What This Rule Does

This rule evaluates all **ingress-nginx Deployments** across all namespaces in a Kubernetes
cluster for exposure to **CVE-2025-1974 (IngressNightmare)** — a critical CVSS 9.8 vulnerability.

It performs three parallel data collections via the Kubernetes API:
- All `ingress-nginx` **Deployments** (cluster-wide)
- All **ValidatingWebhookConfigurations** (admission webhooks)
- All **Helm release Secrets** (owner=helm label filter)

After collecting, it joins and analyzes the data to determine whether each ingress-nginx
instance is:
- Running a **patched version** (≥ v1.11.5 or ≥ v1.12.1)
- Has the **ValidatingWebhookConfiguration disabled**
- Is **managed by Helm** with a known remediated release

Each ingress-nginx instance is then marked:
- ✅ **COMPLIANT** — if a valid remediation is detected
- ❌ **NON_COMPLIANT** — with exact patch command if it remains vulnerable

### Target System
**Kubernetes** (any distribution) — tested with `kind-kind` clusters.

### Compliance Framework Alignment
- CVE-2025-1974 (IngressNightmare) — ingress-nginx CVSS 9.8
- CIS Kubernetes Benchmark (Admission Controller hardening)
- NIST SP 800-190 (Container Security)

### Key Benefits
- Zero-touch discovery — no manual configuration needed per namespace
- Detects all three remediation strategies (version patch, webhook disable, Helm upgrade)
- Provides exact `kubectl` or `helm` patch commands for NON_COMPLIANT instances
- Standard ComplianceCow schema output for downstream reporting

### When To Use This Rule
- After a new Kubernetes cluster is provisioned
- During routine vulnerability scanning cycles
- As part of a post-incident assessment after CVE-2025-1974 disclosure
- In CI/CD pipelines to gate on ingress-nginx compliance

---

## 2. Rule Architecture

### Rule Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                   CVE20251974IngressNightmareAssessment              │
│                                                                     │
│  INPUTS                     TASKS                       OUTPUTS     │
│  ──────                     ─────                       ───────     │
│                                                                     │
│  fetch_deployments_      ┌──────────────────┐                       │
│  RequestConfigFile  ───► │ fetch_deployments │──┐                   │
│                          │ (ExecuteHttpV2)   │  │                   │
│                          └──────────────────┘  │                   │
│                                                 ▼                   │
│  flatten_deployments_    ┌──────────────────────┐                   │
│  JQConfigFile       ───► │ flatten_deployments   │──┐               │
│                          │ (ExtractDataJQV2)     │  │               │
│                          └──────────────────────┘  │               │
│                                                     │               │
│  fetch_webhooks_         ┌──────────────────┐       │               │
│  RequestConfigFile  ───► │  fetch_webhooks  │──┐    │               │
│                          │ (ExecuteHttpV2)  │  │    │               │
│                          └──────────────────┘  │    │               │
│                                                 ▼    │               │
│  flatten_webhooks_       ┌──────────────────────┐   │               │
│  JQConfigFile       ───► │  flatten_webhooks    │──┐│               │
│                          │  (ExtractDataJQV2)   │  ││               │
│                          └──────────────────────┘  ││               │
│                                                     ▼▼              │
│                          ┌────────────────────────────┐             │
│  join_deployments_       │  join_deployments_webhooks │             │
│  webhooks_SQLConfig ───► │    (ExecuteSqlQueryV2)     │──┐          │
│  sql_output_format  ───► └────────────────────────────┘  │          │
│                                                           │          │
│  fetch_helm_secrets_     ┌──────────────────────┐         │          │
│  RequestConfigFile  ───► │  fetch_helm_secrets  │──┐      │          │
│                          │  (ExecuteHttpV2)     │  │      │          │
│                          └──────────────────────┘  │      │          │
│                                                     ▼      │          │
│  flatten_helm_           ┌────────────────────────────┐   │          │
│  secrets_JQConfigFile ►  │  flatten_helm_secrets      │──┐│          │
│                          │  (ExtractDataJQV2)         │  ││          │
│                          └────────────────────────────┘  ││          │
│                                                           ▼▼         │
│  join_helm_              ┌────────────────────────────────┐          │
│  compliance_SQLConfig ►  │      join_helm_compliance      │          │
│  sql_output_format    ►  │      (ExecuteSqlQueryV2)       │──┐       │
│                          └────────────────────────────────┘  │       │
│                                                               ▼       │
│  map_standard_           ┌────────────────────────────────────┐      │
│  schema_JQTransform  ──► │       map_standard_schema          │─────►│ CVE20251974
│  map_standard_           │       (TransformDataWithJQ)        │      │ ComplianceReport
│  schema_OutputMethod ──► └────────────────────────────────────┘      │
│                                                                  ────►│ LogFile
│                                                                  ────►│ CompliancePCT_
│                                                                  ────►│ ComplianceStatus_
└─────────────────────────────────────────────────────────────────────┘
```

### Task Sequence & Dependencies

| Step | Alias | Task | Depends On |
|------|-------|------|------------|
| 1 | `fetch_deployments` | `ExecuteHttpRequestV2` | Rule Input |
| 2 | `flatten_deployments` | `ExtractDataUsingJQV2` | Step 1 |
| 3 | `fetch_webhooks` | `ExecuteHttpRequestV2` | Rule Input |
| 4 | `flatten_webhooks` | `ExtractDataUsingJQV2` | Step 3 |
| 5 | `fetch_helm_secrets` | `ExecuteHttpRequestV2` | Rule Input |
| 6 | `flatten_helm_secrets` | `ExtractDataUsingJQV2` | Step 5 |
| 7 | `join_deployments_webhooks` | `ExecuteSqlQueryV2` | Steps 2 + 4 |
| 8 | `join_helm_compliance` | `ExecuteSqlQueryV2` | Steps 7 + 6 |
| 9 | `map_standard_schema` | `TransformDataWithJQ` | Step 8 |

### Architecture Decisions
- **Parallel HTTP fetches**: Deployments, Webhooks, and Helm Secrets are fetched independently.
- **JQ flattening before SQL**: Raw Kubernetes API responses are flattened before SQL joins to ensure flat tabular structure.
- **Two-phase SQL join**: First join correlates deployment↔webhook; second join adds Helm data and computes final compliance.
- **Standard schema transformation**: Final JQ transform enforces ComplianceCow standard output schema.

---

## 3. Inputs

| # | Input Name | Data Type | Required | Format | Default | Description |
|---|-----------|-----------|----------|--------|---------|-------------|
| 1 | `fetch_deployments_RequestConfigFile` | `HTTP_CONFIG` | ✅ Yes | TOML | — | Kubernetes API request config for listing all Deployments cluster-wide |
| 2 | `flatten_deployments_JQConfigFile` | `FILE` | ✅ Yes | TOML | — | JQ expression config to extract name, namespace, image, version labels, webhook args, and Helm metadata from Deployment API response |
| 3 | `fetch_webhooks_RequestConfigFile` | `HTTP_CONFIG` | ✅ Yes | TOML | — | Kubernetes API request config for listing all ValidatingWebhookConfigurations |
| 4 | `flatten_webhooks_JQConfigFile` | `FILE` | ✅ Yes | TOML | — | JQ expression config to extract webhook names for join |
| 5 | `fetch_helm_secrets_RequestConfigFile` | `HTTP_CONFIG` | ✅ Yes | TOML | — | Kubernetes API request config for listing Secrets with `owner=helm` label |
| 6 | `flatten_helm_secrets_JQConfigFile` | `FILE` | ✅ Yes | TOML | — | JQ expression config to extract Helm release metadata |
| 7 | `join_deployments_webhooks_SQLConfig` | `FILE` | ✅ Yes | TOML | — | SQL query config to LEFT JOIN flattened deployments with webhooks |
| 8 | `join_helm_compliance_SQLConfig` | `FILE` | ✅ Yes | TOML | — | SQL query config to LEFT JOIN deployment+webhook data with Helm secrets; determines ComplianceStatus |
| 9 | `sql_output_format` | `STRING` | ✅ Yes | — | `JSON` | Output format for SQL task results. Allowed: `JSON`, `CSV`, `PARQUET` |
| 10 | `map_standard_schema_JQTransform` | `JQ_EXPRESSION` | ✅ Yes | — | See rule spec | JQ expression to transform raw compliance data into ComplianceCow standard schema |
| 11 | `map_standard_schema_OutputMethod` | `STRING` | ✅ Yes | — | `ALL` | Output method for transform task. Allowed: `ALL`, `FIRST` |

### Input File Format Specifications

**HTTP_CONFIG (TOML) — Example for `fetch_deployments_RequestConfigFile`:**
```toml
[request]
method = "GET"
url = "https://<k8s-api-server>/apis/apps/v1/deployments?labelSelector=app.kubernetes.io%2Fname%3Dingress-nginx"

[request.headers]
Authorization = "Bearer <service-account-token>"
Accept = "application/json"

[tls]
insecure_skip_verify = true
```

**FILE (TOML) — Example for `flatten_deployments_JQConfigFile`:**
```toml
[jq]
expression = '.items[] | { DeploymentName: .metadata.name, Namespace: .metadata.namespace, ... }'
```

---

## 4. Tasks

### Task 1: `fetch_deployments` (ExecuteHttpRequestV2)
- **Purpose:** Calls the Kubernetes API server to retrieve all `apps/v1` Deployments cluster-wide that are labeled as `ingress-nginx`.
- **App Type:** `httprequest`
- **Input:** `fetch_deployments_RequestConfigFile` (TOML HTTP config)
- **Output:** Raw Kubernetes Deployments API JSON response
- **Error Handling:** If Kubernetes API is unreachable or returns 401/403, the task fails. Verify bearer token permissions.

---

### Task 2: `flatten_deployments` (ExtractDataUsingJQV2)
- **Purpose:** Flattens the raw Kubernetes Deployments API response into a flat JSON array, extracting fields: `DeploymentName`, `Namespace`, `AppName`, `AppVersion`, `HelmInstance`, `WebhookArgPresent`, etc.
- **App Type:** `nocredapp`
- **Input:** Output file from `fetch_deployments` + `flatten_deployments_JQConfigFile`
- **Output:** Flat JSON array of ingress-nginx deployment records
- **Error Handling:** If JQ expression fails, verify the API response structure matches the expected Kubernetes API format.

---

### Task 3: `fetch_webhooks` (ExecuteHttpRequestV2)
- **Purpose:** Calls the Kubernetes `admissionregistration.k8s.io/v1` API to list all `ValidatingWebhookConfigurations` in the cluster.
- **App Type:** `httprequest`
- **Input:** `fetch_webhooks_RequestConfigFile` (TOML HTTP config)
- **Output:** Raw ValidatingWebhookConfiguration list JSON
- **Error Handling:** Ensure the service account has `list` permission on `admissionregistration.k8s.io/validatingwebhookconfigurations`.

---

### Task 4: `flatten_webhooks` (ExtractDataUsingJQV2)
- **Purpose:** Extracts webhook names from the ValidatingWebhookConfiguration list for use in the SQL join.
- **App Type:** `nocredapp`
- **Input:** Output file from `fetch_webhooks` + `flatten_webhooks_JQConfigFile`
- **Output:** Flat JSON array of webhook names
- **Error Handling:** If no webhooks are found, the output is an empty array — this is valid and means the webhook check will mark deployments accordingly.

---

### Task 5: `fetch_helm_secrets` (ExecuteHttpRequestV2)
- **Purpose:** Queries Kubernetes Secrets labeled with `owner=helm` to detect which ingress-nginx releases are Helm-managed.
- **App Type:** `httprequest`
- **Input:** `fetch_helm_secrets_RequestConfigFile` (TOML HTTP config)
- **Output:** Raw Kubernetes Secrets list JSON
- **Error Handling:** Ensure the service account has `list` permission on `secrets` in all namespaces.

---

### Task 6: `flatten_helm_secrets` (ExtractDataUsingJQV2)
- **Purpose:** Extracts Helm release metadata (release name, namespace, chart version) for correlation with deployments.
- **App Type:** `nocredapp`
- **Input:** Output file from `fetch_helm_secrets` + `flatten_helm_secrets_JQConfigFile`
- **Output:** Flat JSON array of Helm release records
- **Error Handling:** If no Helm secrets exist, the output is an empty array — meaning no Helm remediation will be detected.

---

### Task 7: `join_deployments_webhooks` (ExecuteSqlQueryV2)
- **Purpose:** Performs a `LEFT JOIN` between flattened deployments (`inputfile1`) and flattened webhooks (`inputfile2`) to determine whether each ingress-nginx deployment has a corresponding ValidatingWebhookConfiguration.
- **App Type:** `nocredapp`
- **Input:** `flatten_deployments` output (InputFile1), `flatten_webhooks` output (InputFile2), `join_deployments_webhooks_SQLConfig`
- **Output:** Enriched deployment records with `WebhookConfigExists` flag
- **SQL Pattern:**
```sql
SELECT d.*, CASE WHEN w.WebhookName IS NOT NULL THEN true ELSE false END AS WebhookConfigExists
FROM inputfile1 d
LEFT JOIN inputfile2 w ON d.HelmInstance = w.WebhookName
```
- **Error Handling:** Both input files must be flat JSON arrays. If either is nested, re-check the JQ flatten tasks.

---

### Task 8: `join_helm_compliance` (ExecuteSqlQueryV2)
- **Purpose:** Performs a `LEFT JOIN` between the deployment+webhook data and Helm secrets to detect Helm-managed releases. Computes final `ComplianceStatus` (`COMPLIANT` / `NON_COMPLIANT`) and `RemediationStatus` based on version, webhook state, and Helm presence.
- **App Type:** `nocredapp`
- **Input:** `join_deployments_webhooks` output (InputFile1), `flatten_helm_secrets` output (InputFile2), `join_helm_compliance_SQLConfig`
- **Output:** Final compliance determination records
- **Compliance Logic:**
  - `COMPLIANT` if: AppVersion ≥ v1.11.5 OR AppVersion ≥ v1.12.1 → `RemediationStatus = PATCHED_VERSION`
  - `COMPLIANT` if: WebhookConfigExists = false → `RemediationStatus = WEBHOOK_DISABLED`
  - `NON_COMPLIANT` if: vulnerable version AND webhook active AND no Helm remediation

---

### Task 9: `map_standard_schema` (TransformDataWithJQ)
- **Purpose:** Transforms the raw compliance records into the ComplianceCow standard output schema. Adds dynamic `EvaluatedTime`, constructs `ChecksPerformed` as a JSON object, generates exact `PatchContent` commands, and populates all mandatory ComplianceCow fields.
- **App Type:** `nocredapp`
- **Input:** `join_helm_compliance` output + `map_standard_schema_JQTransform` + `map_standard_schema_OutputMethod`
- **Output:** `CVE20251974ComplianceReport` (standard schema JSON), `CompliancePCT_`, `ComplianceStatus_`, `LogFile`
- **Standard Schema Fields Populated:**
  `System`, `Source`, `ResourceID`, `ResourceName`, `ResourceType`, `ResourceLocation`, `ResourceTags`, `ClusterName`, `NameSpace`, `CVE`, `ChecksPerformed`, `MatchedRemediation`, `AffectedReason`, `Remediation`, `PatchContent`, `ValidationStatusCode`, `ValidationStatusNotes`, `ComplianceStatus`, `ComplianceStatusReason`, `EvaluatedTime`, `UserAction`, `ActionStatus`, `ActionResponseURL`, `TicketId`, `TicketCreatedDate`, `TicketClosedDate`

---

## 5. Outputs

| # | Output Name | Data Type | Required | Description |
|---|------------|-----------|----------|-------------|
| 1 | `CVE20251974ComplianceReport` | `FILE` | ✅ Yes | Final compliance assessment output for CVE-2025-1974 across all ingress-nginx instances (standard schema JSON) |
| 2 | `LogFile` | `FILE` | ✅ Yes | Execution log file for debugging and audit trail |
| 3 | `CompliancePCT_` | Internal | ✅ Yes | Compliance percentage: `(COMPLIANT count / total count) × 100` |
| 4 | `ComplianceStatus_` | Internal | ✅ Yes | Overall rule compliance status (`COMPLIANT` / `NON_COMPLIANT` / `NOT_DETERMINED`) |

### Output Schema — `CVE20251974ComplianceReport`

```json
{
  "System": "kubernetes",
  "Source": "compliancecow",
  "ResourceID": "ingress-nginx/ingress-nginx-controller",
  "ResourceName": "ingress-nginx-controller",
  "ResourceType": "Deployment",
  "ResourceLocation": "ingress-nginx",
  "ResourceTags": "app.kubernetes.io/name=ingress-nginx,app.kubernetes.io/instance=ingress-nginx",
  "ClusterName": "kind-kind",
  "NameSpace": "ingress-nginx",
  "CVE": "CVE-2025-1974",
  "ChecksPerformed": {
    "VersionCheck": "v1.10.1",
    "WebhookArgPresent": true,
    "WebhookConfigExists": true,
    "ManagedByHelm": false,
    "HelmReleaseFound": false
  },
  "MatchedRemediation": "None",
  "AffectedReason": "ingress-nginx version v1.10.1 is <= v1.11.4 or <= v1.12.0 and validating webhook is active (CVE-2025-1974)",
  "Remediation": "Upgrade ingress-nginx to v1.11.5+ or v1.12.1+, or disable the ValidatingWebhookConfiguration",
  "PatchContent": "kubectl set image deployment/ingress-nginx-controller controller=registry.k8s.io/ingress-nginx/controller:v1.12.1 -n ingress-nginx",
  "ValidationStatusCode": "INGX_VER_VULN",
  "ValidationStatusNotes": "ingress-nginx v1.10.1 is vulnerable to CVE-2025-1974 (IngressNightmare) - webhook active",
  "ComplianceStatus": "NON_COMPLIANT",
  "ComplianceStatusReason": "Version v1.10.1 is vulnerable to CVE-2025-1974 (IngressNightmare). Webhook is active and no remediation detected.",
  "EvaluatedTime": "2026-05-12T13:02:00Z",
  "UserAction": "",
  "ActionStatus": "",
  "ActionResponseURL": "",
  "TicketId": "",
  "TicketCreatedDate": "",
  "TicketClosedDate": ""
}
```

---

## 6. Configuration

### Application Type & Environment
```yaml
appType: httprequest
environment: logical
execlevel: app
annotateType: httprequest
```

### Required Permissions (Kubernetes Service Account)
The service account used in the HTTP bearer token must have the following RBAC permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cve-2025-1974-assessor
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["list", "get"]
  - apiGroups: ["admissionregistration.k8s.io"]
    resources: ["validatingwebhookconfigurations"]
    verbs: ["list", "get"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["list", "get"]
```

### System Prerequisites
- Kubernetes API server must be accessible from the ComplianceCow execution environment
- Service Account token with cluster-wide read permissions
- ingress-nginx must be deployed using standard Kubernetes labels (`app.kubernetes.io/name=ingress-nginx`)
- TLS verification can be disabled via `insecure_skip_verify = true` in the TOML HTTP config

---

## 7. Usage Examples

### Basic Usage

**Step 1:** Configure `fetch_deployments_RequestConfigFile.toml`:
```toml
[request]
method = "GET"
url = "https://10.96.0.1/apis/apps/v1/deployments?labelSelector=app.kubernetes.io%2Fname%3Dingress-nginx"

[request.headers]
Authorization = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
Accept = "application/json"

[tls]
insecure_skip_verify = true
```

**Step 2:** Configure `fetch_webhooks_RequestConfigFile.toml`:
```toml
[request]
method = "GET"
url = "https://10.96.0.1/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations"

[request.headers]
Authorization = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
Accept = "application/json"

[tls]
insecure_skip_verify = true
```

**Step 3:** Set `sql_output_format` to `JSON` and `map_standard_schema_OutputMethod` to `ALL`.

### Advanced — Multi-cluster Assessment
- Run the rule once per cluster by providing different `fetch_*_RequestConfigFile` inputs pointing to different API servers.
- Aggregate `CVE20251974ComplianceReport` outputs across clusters for a unified view.

### Best Practices
- Store bearer tokens as Kubernetes Secrets and reference them via environment variable injection.
- Schedule this rule to run **daily** to catch newly deployed vulnerable versions.
- Use `sql_output_format = "PARQUET"` for large clusters with hundreds of deployments for efficient downstream processing.
- Review `LogFile` output on any failure before modifying inputs.

---

## 8. I/O Mapping

| Source | Direction | Destination |
|--------|-----------|-------------|
| `*.Input.fetch_deployments_RequestConfigFile` | → | `fetch_deployments.Input.RequestConfigFile` |
| `fetch_deployments.Output.OutputFile` | → | `flatten_deployments.Input.InputFile` |
| `*.Input.flatten_deployments_JQConfigFile` | → | `flatten_deployments.Input.JQConfigFile` |
| `*.Input.fetch_webhooks_RequestConfigFile` | → | `fetch_webhooks.Input.RequestConfigFile` |
| `fetch_webhooks.Output.OutputFile` | → | `flatten_webhooks.Input.InputFile` |
| `*.Input.flatten_webhooks_JQConfigFile` | → | `flatten_webhooks.Input.JQConfigFile` |
| `*.Input.fetch_helm_secrets_RequestConfigFile` | → | `fetch_helm_secrets.Input.RequestConfigFile` |
| `fetch_helm_secrets.Output.OutputFile` | → | `flatten_helm_secrets.Input.InputFile` |
| `*.Input.flatten_helm_secrets_JQConfigFile` | → | `flatten_helm_secrets.Input.JQConfigFile` |
| `flatten_deployments.Output.OutputFile` | → | `join_deployments_webhooks.Input.InputFile1` |
| `flatten_webhooks.Output.OutputFile` | → | `join_deployments_webhooks.Input.InputFile2` |
| `*.Input.join_deployments_webhooks_SQLConfig` | → | `join_deployments_webhooks.Input.SQLConfig` |
| `*.Input.sql_output_format` | → | `join_deployments_webhooks.Input.OutputFileFormat` |
| `join_deployments_webhooks.Output.OutputFile` | → | `join_helm_compliance.Input.InputFile1` |
| `flatten_helm_secrets.Output.OutputFile` | → | `join_helm_compliance.Input.InputFile2` |
| `*.Input.join_helm_compliance_SQLConfig` | → | `join_helm_compliance.Input.SQLConfig` |
| `*.Input.sql_output_format` | → | `join_helm_compliance.Input.OutputFileFormat` |
| `join_helm_compliance.Output.OutputFile` | → | `map_standard_schema.Input.InputFile` |
| `*.Input.map_standard_schema_JQTransform` | → | `map_standard_schema.Input.JQTransform` |
| `*.Input.map_standard_schema_OutputMethod` | → | `map_standard_schema.Input.OutputMethod` |
| `map_standard_schema.Output.TransformedFile` | → | `*.Output.CVE20251974ComplianceReport` |
| `map_standard_schema.Output.CompliancePCT_` | → | `*.Output.CompliancePCT_` |
| `map_standard_schema.Output.ComplianceStatus_` | → | `*.Output.ComplianceStatus_` |
| `map_standard_schema.Output.LogFile` | → | `*.Output.LogFile` |

---

## 9. Compliance Schema

### Validation Status Codes

| ValidationStatusCode | ValidationStatusNotes | ComplianceStatus | ComplianceStatusReason |
|---------------------|-----------------------|-----------------|----------------------|
| `INGX_VER_PATCHED` | ingress-nginx `{version}` is a patched version not affected by CVE-2025-1974 | `COMPLIANT` | Version `{version}` is patched and not vulnerable to CVE-2025-1974 |
| `INGX_VER_VULN` | ingress-nginx `{version}` is vulnerable to CVE-2025-1974 (IngressNightmare) - webhook active | `NON_COMPLIANT` | Version `{version}` is vulnerable. Webhook is active and no remediation detected |

### Compliance Percentage Calculation
```
TotalCount     = COUNT(COMPLIANT) + COUNT(NON_COMPLIANT)
CompliantCount = COUNT(ComplianceStatus = 'COMPLIANT')
CompliancePCT  = (CompliantCount / TotalCount) * 100

ComplianceStatus_:
  - COMPLIANT      → 100%
  - NON_COMPLIANT  → 0% to < 100%
  - NOT_DETERMINED → No records found
```

---

## 10. Troubleshooting

### Common Issues

| Issue | Symptom | Solution |
|-------|---------|----------|
| API authentication failure | `fetch_deployments` returns 401 | Refresh the bearer token in `RequestConfigFile` |
| Insufficient RBAC | `fetch_webhooks` or `fetch_helm_secrets` returns 403 | Bind the `cve-2025-1974-assessor` ClusterRole to the service account |
| JQ flatten fails | `flatten_deployments` task fails | Verify the Kubernetes API response structure — check for API version changes in newer k8s releases |
| Empty compliance report | `CVE20251974ComplianceReport` has 0 records | Confirm ingress-nginx is labeled with `app.kubernetes.io/name=ingress-nginx` |
| SQL join produces no rows | `join_deployments_webhooks` output is empty | Ensure both `flatten_deployments` and `flatten_webhooks` produce non-empty flat arrays |
| TLS errors | `fetch_*` tasks fail with certificate errors | Set `insecure_skip_verify = true` in the TOML HTTP config or provide a valid CA bundle |
| Wrong cluster targeted | Reports show unexpected deployments | Verify the API server URL in all three `RequestConfigFile` inputs |

### Performance Considerations
- Large clusters (1000+ deployments): Use `sql_output_format = "PARQUET"` for faster SQL processing.
- High latency to API server: Increase HTTP timeout in the `RequestConfigFile` TOML.

### Support
- Check the `LogFile` output for detailed task-level execution traces.
- Open a support ticket via ComplianceCow portal for platform-level issues.

---

## 11. Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-05-12 | ComplianceCow | Initial release — CVE-2025-1974 IngressNightmare assessment |

---

## 12. References

- 🔗 [CVE-2025-1974 NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2025-1974)
- 🔗 [ingress-nginx Security Advisory](https://github.com/kubernetes/ingress-nginx/security/advisories)
- 🔗 [Kubernetes API — Deployments](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/deployment-v1/)
- 🔗 [Kubernetes API — ValidatingWebhookConfiguration](https://kubernetes.io/docs/reference/kubernetes-api/extend-resources/validating-webhook-configuration-v1/)
- 🔗 [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- 🔗 [Helm Secrets Structure](https://helm.sh/docs/topics/kubernetes_apis/)
- 🔗 [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- 🔗 [NIST SP 800-190 — Container Security](https://csrc.nist.gov/publications/detail/sp/800/190/final)
- 🔗 [ComplianceCow Documentation](https://compliancecow.live)
