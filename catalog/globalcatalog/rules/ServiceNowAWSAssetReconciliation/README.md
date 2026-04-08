# ServiceNowAWSAssetReconciliation

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![AppType](https://img.shields.io/badge/apptype-httprequest-green.svg)
![Environment](https://img.shields.io/badge/environment-logical-orange.svg)
![Status](https://img.shields.io/badge/status-ACTIVE-success.svg)

**Last Updated:** 2026-04-08

---

## Table of Contents

- [Overview](#overview)
- [Rule Architecture](#rule-architecture)
- [Inputs](#inputs)
- [Tasks](#tasks)
- [Outputs](#outputs)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [I/O Mapping](#io-mapping)
- [Compliance Logic](#compliance-logic)
- [Troubleshooting](#troubleshooting)
- [Version History](#version-history)
- [Authors](#authors)
- [References](#references)

---

## Overview

### Purpose

Reconcile VM assets between ServiceNow CMDB and AWS EC2 to identify discrepancies and ensure asset inventory accuracy.

### Description

This rule fetches VM assets from ServiceNow CMDB and EC2 instances from AWS, performs reconciliation based on hostname matching, and generates a comprehensive compliance report identifying assets present in both systems (COMPLIANT) or missing from either system (NON_COMPLIANT). Includes presence flags (PresentInServiceNow, PresentInAWS) for complete audit trail.

### Target Systems

- **ServiceNow CMDB** - Configuration Management Database for VM asset inventory
- **AWS EC2** - Amazon Elastic Compute Cloud for runtime VM instances

### Key Benefits

- ✅ **Complete Asset Visibility** - Union of all unique assets from both systems
- ✅ **Automated Reconciliation** - Hostname-based matching with case-insensitive comparison
- ✅ **Compliance Tracking** - Clear identification of compliant vs non-compliant assets
- ✅ **Audit Trail** - Presence flags for both systems with detailed status codes
- ✅ **Standard Schema** - ComplianceCow compliant output format

### Use Cases

- **IT Asset Management** - Ensure all runtime VMs are properly documented in CMDB
- **Compliance Auditing** - Verify asset inventory accuracy for compliance requirements
- **Shadow IT Detection** - Identify AWS instances not registered in ServiceNow
- **CMDB Cleanup** - Find obsolete CMDB entries for decommissioned AWS instances
- **Change Management** - Track discrepancies between planned and actual infrastructure

### When to Use This Rule

- Regular asset inventory audits (daily, weekly, monthly)
- Before compliance reporting periods
- After major infrastructure changes
- During asset lifecycle reviews
- For continuous compliance monitoring

---

## Rule Architecture

### Workflow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Rule Execution Flow                          │
└─────────────────────────────────────────────────────────────────┘

    ┌──────────────────┐         ┌──────────────────┐
    │   ServiceNow     │         │      AWS EC2     │
    │      CMDB        │         │   DescribeInst.  │
    └────────┬─────────┘         └────────┬─────────┘
             │                            │
             │ GET /api/now/table/        │ POST DescribeInstances
             │ cmdb_ci_vm_instance        │
             │                            │
             ▼                            ▼
    ┌──────────────────┐         ┌──────────────────┐
    │fetch_servicenow  │         │  fetch_aws_ec2   │
    │      _vms        │         │                  │
    │ ExecuteHttpReq   │         │ ExecuteHttpReq   │
    └────────┬─────────┘         └────────┬─────────┘
             │                            │
             │ OutputFile (VMs)           │ OutputFile (EC2s)
             │                            │
             └──────────┬─────────────────┘
                        │
                        ▼
              ┌──────────────────┐
              │ reconcile_assets │
              │ ExecuteSqlQuery  │
              │ FULL OUTER JOIN  │
              └────────┬─────────┘
                       │
                       │ Reconciled Data
                       │ (Union + Status)
                       ▼
           ┌──────────────────────────┐
           │ transform_to_standard    │
           │         _schema          │
           │   TransformDataWithJQ    │
           └────────┬─────────────────┘
                    │
                    ▼
         ┌──────────────────────────┐
         │ StandardComplianceReport │
         │    CompliancePCT_        │
         │   ComplianceStatus_      │
         │       LogFile            │
         └──────────────────────────┘
```

### Data Flow

1. **Input Phase** - Rule accepts 6 configuration inputs
2. **Task 1: fetch_servicenow_vms** - Retrieves VM data from ServiceNow CMDB
3. **Task 2: fetch_aws_ec2** - Retrieves EC2 instance data from AWS
4. **Task 3: reconcile_assets** - Performs SQL-based reconciliation with FULL OUTER JOIN
5. **Task 4: transform_to_standard_schema** - Converts to ComplianceCow standard format
6. **Output Phase** - Generates compliance report with presence flags and status

### Architecture Decisions

- **FULL OUTER JOIN Strategy** - Ensures no assets are missed from either system
- **Hostname Matching** - Case-insensitive comparison with TRIM for reliability
- **Two-Stage Processing** - Separation of reconciliation logic and schema transformation
- **Standard Schema Compliance** - Follows ComplianceCow mandatory field requirements
- **Presence Flags** - Explicit Yes/No indicators for audit trail

---

## Inputs

### Input Summary

| Input Name                 | Data Type      | Required | Format | Description                                |
| -------------------------- | -------------- | -------- | ------ | ------------------------------------------ |
| ServiceNowRequestConfig    | HTTP_CONFIG    | ✅ Yes   | TOML   | ServiceNow CMDB API configuration          |
| AWSRequestConfig           | HTTP_CONFIG    | ✅ Yes   | TOML   | AWS EC2 API configuration                  |
| ReconciliationSQLQuery     | SQL_EXPRESSION | ✅ Yes   | SQL    | Reconciliation query with compliance logic |
| ReconciliationOutputFormat | STRING         | ✅ Yes   | -      | Output format (JSON, CSV, PARQUET)         |
| StandardSchemaTransform    | JQ_EXPRESSION  | ✅ Yes   | JQ     | JQ transformation to standard schema       |
| TransformOutputMethod      | STRING         | ✅ Yes   | -      | Output method (ALL or FIRST)               |

---

### 1. ServiceNowRequestConfig

**Type:** HTTP_CONFIG (TOML)
**Required:** Yes
**Description:** ServiceNow CMDB API configuration for fetching VM assets

**Configuration Structure:**

```toml
[Variables]
Method = "GET"
TableName = "cmdb_ci_vm_instance"

[Request]
URL = "<<application.AppURL>>/api/now/table/<<TableName>>"
Method = "<<Method>>"
ContentType = "application/json"
Redirect = true
CredentialType = "BasicAuthentication"
TimeOut = 30
Verify = true
MaxWorkers = 5

[Request.Headers]
Accept = "application/json"

[Request.Params]
sysparm_query = "operational_status=1^install_status=1"
sysparm_fields = "sys_id,name,vm_inst_id,ip_address,os,cpu_count,ram,location"
sysparm_limit = "10000"
```

**Key Parameters:**

- `sysparm_query` - Filters for operational and installed VMs
- `sysparm_fields` - Specific fields to retrieve from CMDB
- `sysparm_limit` - Maximum number of records (10,000)

**Authentication:** BasicAuthentication (username/password)

---

### 2. AWSRequestConfig

**Type:** HTTP_CONFIG (TOML)
**Required:** Yes
**Description:** AWS EC2 API configuration for fetching EC2 instances

**Configuration Structure:**

```toml
[Variables]
Method = "POST"
Action = "DescribeInstances"
Version = "2016-11-15"

[Request]
URL = "<<application.AppURL>>"
Method = "<<Method>>"
ContentType = "application/x-www-form-urlencoded"
Redirect = true
CredentialType = "AWSSignature"
TimeOut = 30
Verify = true
MaxWorkers = 5

[Request.Params]
Action = "<<Action>>"
Version = "<<Version>>"
```

**Key Parameters:**

- `Action` - DescribeInstances (retrieves all EC2 instances)
- `Version` - AWS API version (2016-11-15)

**Authentication:** AWSSignature (AWS Access Key ID and Secret Access Key)

---

### 3. ReconciliationSQLQuery

**Type:** SQL_EXPRESSION
**Required:** Yes
**Description:** SQL query to reconcile ServiceNow VMs and AWS EC2 instances based on hostname matching

**Query Logic:**

```sql
SELECT 
    COALESCE(inputfile1.name, json_extract(inputfile2.PrivateDnsName, '$')) AS AssetName,
    COALESCE(inputfile1.sys_id, inputfile2.InstanceId) AS ResourceID,
  
    -- ServiceNow Fields
    inputfile1.name AS ServiceNowName,
    inputfile1.sys_id AS ServiceNowID,
    inputfile1.ip_address AS ServiceNowIPAddress,
    inputfile1.os AS ServiceNowOS,
  
    -- AWS Fields
    inputfile2.InstanceId AS AWSEC2InstanceID,
    inputfile2.InstanceType AS AWSEC2InstanceType,
    json_extract(inputfile2.State, '$.Name') AS AWSEC2State,
  
    -- Presence Flags
    CASE WHEN inputfile1.sys_id IS NOT NULL THEN 'Yes' ELSE 'No' END AS PresentInServiceNow,
    CASE WHEN inputfile2.InstanceId IS NOT NULL THEN 'Yes' ELSE 'No' END AS PresentInAWS,
  
    -- Compliance Status
    CASE 
        WHEN inputfile1.sys_id IS NOT NULL AND inputfile2.InstanceId IS NOT NULL THEN 'COMPLIANT'
        WHEN inputfile1.sys_id IS NULL THEN 'NON_COMPLIANT'
        WHEN inputfile2.InstanceId IS NULL THEN 'NON_COMPLIANT'
        ELSE 'NOT_DETERMINED'
    END AS ComplianceStatus
  
FROM inputfile1 
FULL OUTER JOIN inputfile2 
ON LOWER(TRIM(inputfile1.name)) = LOWER(TRIM(json_extract(inputfile2.PrivateDnsName, '$')))
```

**Query Features:**

- FULL OUTER JOIN for complete union of assets
- Case-insensitive hostname matching with TRIM
- Presence flags for both systems
- Compliance status based on presence in both systems
- Validation status codes (BOTH_PRSN, SNOW_MISS, AWS_MISS)

---

### 4. ReconciliationOutputFormat

**Type:** STRING
**Required:** Yes
**Allowed Values:** JSON, CSV, PARQUET
**Default:** JSON
**Description:** Output format for reconciliation results

---

### 5. StandardSchemaTransform

**Type:** JQ_EXPRESSION
**Required:** Yes
**Description:** JQ transformation to map reconciled data to ComplianceCow standard schema

**Transformation Logic:**

```jq
map(. + {
  System: .System,
  Source: .Source,
  ResourceID: .ResourceID,
  ResourceName: .AssetName,
  ResourceType: "VirtualMachine",
  ResourceLocation: (if .ServiceNowLocation then .ServiceNowLocation elif .AWSEC2AvailabilityZone then .AWSEC2AvailabilityZone else "Unknown" end),
  ValidationStatusCode: .ValidationStatusCode,
  ComplianceStatus: .ComplianceStatus,
  ComplianceStatusReason: .ComplianceStatusReason,
  EvaluatedTime: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
  PresentInServiceNow: .PresentInServiceNow,
  PresentInAWS: .PresentInAWS
})
```

---

### 6. TransformOutputMethod

**Type:** STRING
**Required:** Yes
**Allowed Values:** ALL, FIRST
**Default:** ALL
**Description:** Output method for JQ transformation

---

## Tasks

### Task Summary

| Task Alias                   | Task Name            | Purpose                              | App Type    |
| ---------------------------- | -------------------- | ------------------------------------ | ----------- |
| fetch_servicenow_vms         | ExecuteHttpRequestV2 | Fetch VM assets from ServiceNow CMDB | httprequest |
| fetch_aws_ec2                | ExecuteHttpRequestV2 | Fetch EC2 instances from AWS         | httprequest |
| reconcile_assets             | ExecuteSqlQueryV2    | Reconcile assets based on hostname   | nocredapp   |
| transform_to_standard_schema | TransformDataWithJQ  | Transform to standard schema         | nocredapp   |

---

### Task 1: fetch_servicenow_vms

**Task Name:** ExecuteHttpRequestV2
**Alias:** fetch_servicenow_vms
**App Type:** httprequest

**Purpose:** Fetch VM assets from ServiceNow CMDB using Table API

**Description:** Retrieves virtual machine records from ServiceNow CMDB with operational and installed status filters

**Input Requirements:**

- RequestConfigFile (ServiceNowRequestConfig)

**Output:**

- OutputFile - JSON array of VM records from ServiceNow

**Processing Logic:**

1. Connects to ServiceNow instance using BasicAuthentication
2. Queries cmdb_ci_vm_instance table
3. Filters for operational_status=1 and install_status=1
4. Retrieves specified fields (sys_id, name, vm_inst_id, ip_address, os, cpu_count, ram, location)
5. Returns up to 10,000 records

**Error Handling:**

- Automatic retry on 503, 504, 429 status codes
- Max 3 retries with exponential backoff
- 30-second timeout per request

---

### Task 2: fetch_aws_ec2

**Task Name:** ExecuteHttpRequestV2
**Alias:** fetch_aws_ec2
**App Type:** httprequest

**Purpose:** Fetch EC2 instances from AWS using DescribeInstances API

**Description:** Retrieves all EC2 instances from AWS account with instance details

**Input Requirements:**

- RequestConfigFile (AWSRequestConfig)

**Output:**

- OutputFile - JSON array of EC2 instance records

**Processing Logic:**

1. Connects to AWS EC2 endpoint using AWSSignature authentication
2. Calls DescribeInstances API action
3. Retrieves all EC2 instances with full details
4. Returns instance metadata including InstanceId, InstanceType, State, PrivateIpAddress, PrivateDnsName, Platform, Placement

**Error Handling:**

- Automatic retry on 503, 504, 429 status codes
- Max 3 retries with exponential backoff
- 30-second timeout per request

---

### Task 3: reconcile_assets

**Task Name:** ExecuteSqlQueryV2
**Alias:** reconcile_assets
**App Type:** nocredapp (no credentials required)

**Purpose:** Reconcile assets from ServiceNow and AWS based on hostname matching

**Description:** Performs FULL OUTER JOIN to create union of all unique assets with presence flags and compliance status

**Input Requirements:**

- InputFile1 (from fetch_servicenow_vms.Output.OutputFile)
- InputFile2 (from fetch_aws_ec2.Output.OutputFile)
- SQLQuery (ReconciliationSQLQuery)
- OutputFileFormat (ReconciliationOutputFormat)

**Output:**

- OutputFile - Reconciled asset data with compliance status

**Processing Logic:**

1. Loads ServiceNow VM data into inputfile1 table
2. Loads AWS EC2 data into inputfile2 table
3. Executes FULL OUTER JOIN on hostname (case-insensitive with TRIM)
4. Generates presence flags (PresentInServiceNow, PresentInAWS)
5. Calculates compliance status based on presence in both systems
6. Assigns validation status codes (BOTH_PRSN, SNOW_MISS, AWS_MISS)
7. Outputs in JSON format

---

### Task 4: transform_to_standard_schema

**Task Name:** TransformDataWithJQ
**Alias:** transform_to_standard_schema
**App Type:** nocredapp (no credentials required)

**Purpose:** Transform reconciled data to ComplianceCow standard schema

**Description:** Maps all fields to standard schema format with mandatory compliance fields

**Input Requirements:**

- InputFile (from reconcile_assets.Output.OutputFile)
- JQTransform (StandardSchemaTransform)
- OutputMethod (TransformOutputMethod)

**Output:**

- TransformedFile - Standard schema compliance report
- CompliancePCT_ - Compliance percentage
- ComplianceStatus_ - Overall compliance status
- LogFile - Execution log

**Processing Logic:**

1. Reads reconciled asset data from previous task
2. Applies JQ transformation to map to standard schema
3. Adds mandatory ComplianceCow fields:
   - System, Source, ResourceID, ResourceName, ResourceType
   - ResourceLocation, ResourceTags, ResourceURL
   - ValidationStatusCode, ValidationStatusNotes
   - ComplianceStatus, ComplianceStatusReason
   - EvaluatedTime, UserAction, ActionStatus, ActionResponseURL
4. Preserves system-specific fields (ServiceNow and AWS details)
5. Includes presence flags for audit trail
6. Generates auto-timestamp for EvaluatedTime
7. Outputs all transformed records (OutputMethod = ALL)

---

## Outputs

### Output Summary

| Output Name              | Data Type | Description                                                     |
| ------------------------ | --------- | --------------------------------------------------------------- |
| StandardComplianceReport | FILE      | ComplianceCow standard schema report with all reconciled assets |
| CompliancePCT_           | INT       | Compliance percentage from transformation task                  |
| ComplianceStatus_        | STRING    | Overall compliance status from transformation task              |
| LogFile                  | FILE      | Log file from transformation task                               |

---

### 1. StandardComplianceReport

**Type:** FILE (JSON)
**Description:** ComplianceCow standard schema report with all reconciled assets and compliance status

**Schema Structure:**

```json
[
  {
    "System": "servicenow,aws",
    "Source": "compliancecow",
    "ResourceID": "sys_id_or_instance_id",
    "ResourceName": "hostname",
    "ResourceType": "VirtualMachine",
    "ResourceLocation": "location_or_az",
    "ResourceTags": "InstanceType:t2.micro",
    "ResourceURL": "",
    "ServiceNowVMName": "vm-hostname",
    "ServiceNowVMID": "sys_12345",
    "ServiceNowInstanceID": "vm_inst_12345",
    "ServiceNowIPAddress": "10.0.1.100",
    "ServiceNowOS": "Linux",
    "ServiceNowCPU": "4",
    "ServiceNowRAM": "16384",
    "ServiceNowLocation": "datacenter-1",
    "PresentInServiceNow": "Yes",
    "AWSEC2InstanceID": "i-0123456789abcdef0",
    "AWSEC2InstanceType": "t2.micro",
    "AWSEC2State": "running",
    "AWSEC2PrivateIP": "10.0.1.100",
    "AWSEC2Hostname": "ip-10-0-1-100.ec2.internal",
    "AWSEC2Platform": "linux",
    "AWSEC2AvailabilityZone": "us-east-1a",
    "PresentInAWS": "Yes",
    "ValidationStatusCode": "BOTH_PRSN",
    "ValidationStatusNotes": "Asset present in both ServiceNow CMDB and AWS EC2",
    "ComplianceStatus": "COMPLIANT",
    "ComplianceStatusReason": "Asset present in both ServiceNow CMDB and AWS EC2",
    "EvaluatedTime": "2026-04-08T02:15:00Z",
    "UserAction": "",
    "ActionStatus": "",
    "ActionResponseURL": ""
  }
]
```

---

### 2. CompliancePCT_

**Type:** INT
**Description:** Compliance percentage calculated from transformation task

**Calculation:**

```
CompliancePCT = (Number of COMPLIANT assets / Total assets) * 100
```

**Range:** 0-100

---

### 3. ComplianceStatus_

**Type:** STRING
**Description:** Overall compliance status from transformation task

**Possible Values:**

- `COMPLIANT` - All assets present in both systems
- `NON_COMPLIANT` - One or more assets missing from either system
- `NOT_DETERMINED` - Unable to determine compliance status

---

### 4. LogFile

**Type:** FILE (JSON)
**Description:** Log file from transformation task containing execution details and any errors

---

## Configuration

### Application Type

**Primary:** httprequest
**Environment:** logical
**Execution Level:** app

### Required Credentials

#### ServiceNow Credentials (BasicAuthentication)

- **Username** - ServiceNow account username
- **Password** - ServiceNow account password
- **Instance URL** - ServiceNow instance URL (e.g., https://your-instance.service-now.com)

#### AWS Credentials (AWSSignature)

- **Access Key ID** - AWS access key ID
- **Secret Access Key** - AWS secret access key
- **Region Endpoint** - AWS EC2 endpoint URL (e.g., https://ec2.us-east-1.amazonaws.com)

### Permissions Required

#### ServiceNow

- Read access to `cmdb_ci_vm_instance` table
- API access enabled

#### AWS

- `ec2:DescribeInstances` permission
- Read-only access to EC2 service

### Environment Settings

- **Timeout:** 30 seconds per API request
- **Max Workers:** 5 parallel requests
- **Max Retries:** 3 attempts with exponential backoff
- **Retry Conditions:** 503, 504, 429 HTTP status codes

---

## Usage Examples

### Basic Usage

**Scenario:** Daily asset reconciliation audit

```yaml
# Execute rule with credentials
Rule: ServiceNowAWSAssetReconciliation
Inputs:
  - ServiceNowRequestConfig: [configured]
  - AWSRequestConfig: [configured]
  - ReconciliationSQLQuery: [default]
  - ReconciliationOutputFormat: JSON
  - StandardSchemaTransform: [default]
  - TransformOutputMethod: ALL

Applications:
  - ServiceNow: BasicAuthentication (username/password)
  - AWS: AWSSignature (access_key_id/secret_access_key)
```

**Expected Output:**

- Reconciled asset report in JSON format
- Compliance percentage (e.g., 85%)
- Overall compliance status (COMPLIANT or NON_COMPLIANT)

---

### Advanced Configuration

**Scenario:** Custom reconciliation with additional filters

Modify `ServiceNowRequestConfig` to filter by specific location:

```toml
[Request.Params]
sysparm_query = "operational_status=1^install_status=1^location=datacenter-1"
```

Modify `ReconciliationOutputFormat` to CSV for spreadsheet analysis:

```yaml
ReconciliationOutputFormat: CSV
```

---

### Common Use Cases

#### 1. Shadow IT Detection

**Goal:** Find AWS EC2 instances not registered in ServiceNow CMDB

**Filter Output:**

```sql
SELECT * FROM StandardComplianceReport 
WHERE PresentInAWS = 'Yes' AND PresentInServiceNow = 'No'
```

---

#### 2. CMDB Cleanup

**Goal:** Identify obsolete ServiceNow entries for decommissioned AWS instances

**Filter Output:**

```sql
SELECT * FROM StandardComplianceReport 
WHERE PresentInServiceNow = 'Yes' AND PresentInAWS = 'No'
```

---

#### 3. Complete Asset Inventory

**Goal:** Get union of all unique assets from both systems

**Output:** All records in StandardComplianceReport (default behavior)

---

## I/O Mapping

### Input-to-Task Mappings

```yaml
# Task 1: fetch_servicenow_vms
fetch_servicenow_vms.Input.RequestConfigFile := *.Input.ServiceNowRequestConfig

# Task 2: fetch_aws_ec2
fetch_aws_ec2.Input.RequestConfigFile := *.Input.AWSRequestConfig

# Task 3: reconcile_assets
reconcile_assets.Input.InputFile1 := fetch_servicenow_vms.Output.OutputFile
reconcile_assets.Input.InputFile2 := fetch_aws_ec2.Output.OutputFile
reconcile_assets.Input.SQLQuery := *.Input.ReconciliationSQLQuery
reconcile_assets.Input.OutputFileFormat := *.Input.ReconciliationOutputFormat

# Task 4: transform_to_standard_schema
transform_to_standard_schema.Input.InputFile := reconcile_assets.Output.OutputFile
transform_to_standard_schema.Input.JQTransform := *.Input.StandardSchemaTransform
transform_to_standard_schema.Input.OutputMethod := *.Input.TransformOutputMethod
```

### Task-to-Output Mappings

```yaml
*.Output.StandardComplianceReport := transform_to_standard_schema.Output.TransformedFile
*.Output.CompliancePCT_ := transform_to_standard_schema.Output.CompliancePCT_
*.Output.ComplianceStatus_ := transform_to_standard_schema.Output.ComplianceStatus_
*.Output.LogFile := transform_to_standard_schema.Output.LogFile
```

### Data Flow Visualization

```
Rule Inputs
    ├─> ServiceNowRequestConfig ──> fetch_servicenow_vms.Input.RequestConfigFile
    ├─> AWSRequestConfig ──> fetch_aws_ec2.Input.RequestConfigFile
    ├─> ReconciliationSQLQuery ──> reconcile_assets.Input.SQLQuery
    ├─> ReconciliationOutputFormat ──> reconcile_assets.Input.OutputFileFormat
    ├─> StandardSchemaTransform ──> transform_to_standard_schema.Input.JQTransform
    └─> TransformOutputMethod ──> transform_to_standard_schema.Input.OutputMethod

Task Outputs
    fetch_servicenow_vms.Output.OutputFile ──> reconcile_assets.Input.InputFile1
    fetch_aws_ec2.Output.OutputFile ──> reconcile_assets.Input.InputFile2
    reconcile_assets.Output.OutputFile ──> transform_to_standard_schema.Input.InputFile

Rule Outputs
    transform_to_standard_schema.Output.TransformedFile ──> *.Output.StandardComplianceReport
    transform_to_standard_schema.Output.CompliancePCT_ ──> *.Output.CompliancePCT_
    transform_to_standard_schema.Output.ComplianceStatus_ ──> *.Output.ComplianceStatus_
    transform_to_standard_schema.Output.LogFile ──> *.Output.LogFile
```

---

## Compliance Logic

### Validation Status Codes

| Code      | Meaning                                       | Compliance Status |
| --------- | --------------------------------------------- | ----------------- |
| BOTH_PRSN | Asset present in both ServiceNow and AWS      | COMPLIANT         |
| SNOW_MISS | Asset exists in AWS but missing in ServiceNow | NON_COMPLIANT     |
| AWS_MISS  | Asset exists in ServiceNow but missing in AWS | NON_COMPLIANT     |
| STAT_UNKN | Unable to determine status                    | NOT_DETERMINED    |

### Compliance Rules

**Rule 1: Compliant Assets**

- Condition: Asset exists in both ServiceNow CMDB AND AWS EC2
- Status: COMPLIANT
- Code: BOTH_PRSN
- Reason: "Asset present in both ServiceNow CMDB and AWS EC2"

**Rule 2: Missing from ServiceNow**

- Condition: Asset exists in AWS EC2 but NOT in ServiceNow CMDB
- Status: NON_COMPLIANT
- Code: SNOW_MISS
- Reason: "Asset exists in AWS EC2 but missing in ServiceNow CMDB"

**Rule 3: Missing from AWS**

- Condition: Asset exists in ServiceNow CMDB but NOT in AWS EC2
- Status: NON_COMPLIANT
- Code: AWS_MISS
- Reason: "Asset exists in ServiceNow CMDB but missing in AWS EC2"

### Presence Flags

- **PresentInServiceNow:** "Yes" or "No"
- **PresentInAWS:** "Yes" or "No"

These flags provide explicit visibility into asset presence for audit trail purposes.

---

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: ServiceNow Authentication Failure

**Error:** `401 Unauthorized` from ServiceNow API

**Possible Causes:**

- Invalid username or password
- Account locked or disabled
- Insufficient API permissions

**Solutions:**

1. Verify credentials in ServiceNow application configuration
2. Check account status in ServiceNow
3. Ensure account has read access to `cmdb_ci_vm_instance` table
4. Verify API access is enabled for the account

---

#### Issue 2: AWS Authentication Failure

**Error:** `403 Forbidden` or `InvalidAccessKeyId` from AWS

**Possible Causes:**

- Invalid AWS Access Key ID or Secret Access Key
- Missing `ec2:DescribeInstances` permission
- Incorrect region endpoint

**Solutions:**

1. Verify AWS credentials in application configuration
2. Check IAM policy includes `ec2:DescribeInstances` permission
3. Verify AWS region endpoint URL is correct
4. Test credentials using AWS CLI: `aws ec2 describe-instances`

---

#### Issue 3: No Reconciliation Matches

**Symptom:** All assets show as missing from one system

**Possible Causes:**

- Hostname mismatch between ServiceNow and AWS
- Data format issues (e.g., FQDN vs short hostname)
- Empty result from one API call

**Solutions:**

1. Check hostname format in both systems
2. Verify ServiceNow `name` field matches AWS `PrivateDnsName`
3. Review raw output files from fetch tasks
4. Modify SQL query hostname matching logic if needed

---

#### Issue 4: Timeout Errors

**Error:** `TimeoutError` or request timeout

**Possible Causes:**

- Large dataset (>10,000 records)
- Slow API response
- Network connectivity issues

**Solutions:**

1. Reduce `sysparm_limit` in ServiceNow config
2. Increase `TimeOut` value in request configs (e.g., 60 seconds)
3. Adjust `MaxWorkers` for parallel processing
4. Implement pagination in ResponseConfigFile

---

#### Issue 5: SQL Query Execution Failure

**Error:** SQL validation or execution error

**Possible Causes:**

- Invalid SQL syntax
- Missing fields in input files
- JSON extraction issues

**Solutions:**

1. Validate SQL query syntax
2. Check field names match actual API response fields
3. Test SQL query with sample data
4. Review InputFile1 and InputFile2 structures

---

#### Issue 6: Transformation Errors

**Error:** JQ transformation failure

**Possible Causes:**

- Invalid JQ syntax
- Missing fields in reconciliation output
- Type mismatch

**Solutions:**

1. Validate JQ expression syntax
2. Test transformation with sample data using `jq` command
3. Check reconciliation output contains expected fields
4. Review LogFile for detailed error messages

---

### Performance Considerations

**Large Dataset Handling:**

- ServiceNow limit: 10,000 records per request
- Use pagination in ResponseConfigFile for larger datasets
- Adjust MaxWorkers for parallel processing

**Network Optimization:**

- Position execution environment close to APIs
- Use appropriate retry logic for transient failures
- Monitor timeout settings for large responses

---

### Debug Mode

Enable detailed logging by reviewing:

- Task execution logs
- API request/response details
- SQL query execution results
- JQ transformation intermediate output

---

## Version History

| Version | Date       | Changes                                                | Author        |
| ------- | ---------- | ------------------------------------------------------ | ------------- |
| 1.0.0   | 2026-04-08 | Initial release with core reconciliation functionality | [Author Name] |

### Change Log

#### Version 1.0.0 (2026-04-08)

- ✅ Initial rule creation
- ✅ ServiceNow CMDB integration
- ✅ AWS EC2 integration
- ✅ SQL-based reconciliation with FULL OUTER JOIN
- ✅ Presence flags implementation
- ✅ ComplianceCow standard schema transformation
- ✅ Validation status codes (BOTH_PRSN, SNOW_MISS, AWS_MISS)

---

## Authors

**Primary Author(s):**

- Mosi Platt
- Rohith
- Megha Shah
- Raj Krishnamurthy

**Contributors:**

- Shradha Krish
- Ram Manavalan
- Arul G

---

## References

### Related Documentation

- [ComplianceCow Documentation](https://docs.compliancecow.io)
- [ServiceNow Table API Documentation](https://developer.servicenow.com/dev.do#!/reference/api/latest/rest/c_TableAPI)
- [AWS EC2 DescribeInstances API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html)
- [SQL FULL OUTER JOIN Documentation](https://www.sqlite.org/lang_select.html)
- [JQ Manual](https://stedolan.github.io/jq/manual/)

### Compliance Frameworks

- IT Asset Management (ITAM) best practices
- Configuration Management Database (CMDB) standards
- Cloud Asset Inventory compliance requirements

---

## Changelog

All notable changes to this rule will be documented in this section.

**[1.0.0] - 2026-04-08**

- Initial release

---

**Last Updated:** 2026-04-08
**Rule Status:** ACTIVE
**Maintained By:** ComplianceCow Team
