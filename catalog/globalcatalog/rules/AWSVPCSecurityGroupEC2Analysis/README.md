# AWSVPCSecurityGroupEC2Analysis

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Application Type](https://img.shields.io/badge/app-httprequest-green)
![Environment](https://img.shields.io/badge/env-logical-yellow)

## Overview

### Purpose

Analyze AWS VPCs, filter by criteria, identify EC2 instances and their security groups, then determine all EC2 instances sharing those security groups across the account

### Description

This rule retrieves all VPCs from an AWS account, filters them based on user-defined criteria such as tags or names, lists all EC2 instances within those filtered VPCs, identifies associated security groups, determines all EC2 instances sharing those security groups across the account, and generates a comprehensive compliance report with the findings.

### Key Benefits

- **Complete VPC Analysis**: Systematically analyzes VPCs based on custom filtering criteria
- **Security Group Mapping**: Identifies all security groups used by EC2 instances in filtered VPCs
- **Cross-Account Discovery**: Finds ALL EC2 instances across the account that share identified security groups
- **Dual Output**: Provides both standard compliance report and extended raw data for audit trails
- **Automated Compliance**: Generates standardized compliance reports with validation status codes

### Use Cases

- Security group usage analysis across VPCs
- EC2 instance inventory by security group association
- VPC-based resource discovery and compliance reporting
- Security posture assessment for tagged VPCs
- Cross-VPC security group impact analysis

---

## Rule Architecture

### Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                    AWS VPC Security Group EC2 Analysis               │
└─────────────────────────────────────────────────────────────────────┘

[AWS Account]
    │
    ├─► Task 1: fetch_vpcs (ExecuteHttpRequestV2)
    │   └─► Fetch all VPCs from AWS EC2 API
    │       └─► Output: All VPCs in account
    │
    ├─► Task 2: filter_vpcs (FilterDataWithJQ)
    │   └─► Filter: Non-default VPCs with tags
    │       └─► Output: Filtered VPCs matching criteria
    │
    ├─► Task 3: fetch_ec2_in_vpcs (ExecuteHttpRequestV2)
    │   └─► List EC2 instances in filtered VPCs
    │       └─► Output: EC2 instances within filtered VPCs
    │
    ├─► Task 4: extract_security_groups (TransformDataWithJQ)
    │   └─► Extract unique security group IDs
    │       └─► Output: List of unique security groups
    │
    ├─► Task 5: fetch_all_ec2_with_sgs (ExecuteHttpRequestV2)
    │   └─► Find ALL EC2s with those security groups
    │       └─► Output: Complete EC2 population sharing SGs
    │
    └─► Task 6: generate_report (TransformDataWithJQ)
        └─► Generate compliance report
            ├─► Output: ComplianceReport (Standard Schema)
            └─► Output: ExtendedData_EC2Instances (Raw Data)
```

### Task Sequence and Dependencies

1. **fetch_vpcs** → Retrieves all VPCs
2. **filter_vpcs** → Filters VPCs (depends on fetch_vpcs output)
3. **fetch_ec2_in_vpcs** → Gets EC2s in filtered VPCs (depends on filter_vpcs output)
4. **extract_security_groups** → Extracts security group IDs (depends on fetch_ec2_in_vpcs output)
5. **fetch_all_ec2_with_sgs** → Finds all EC2s with those SGs (depends on extract_security_groups output)
6. **generate_report** → Creates compliance report (depends on fetch_all_ec2_with_sgs output)

---

## Inputs

| Input Name                                   | Type               | Required | Description                                                              | Default Value                                           | Example            |
| -------------------------------------------- | ------------------ | -------- | ------------------------------------------------------------------------ | ------------------------------------------------------- | ------------------ |
| `fetch_vpcs_RequestConfigFile`             | HTTP_CONFIG (TOML) | Yes      | AWS EC2 DescribeVpcs API configuration                                   | See configuration file                                  | N/A                |
| `filter_vpcs_JQFilter`                     | JQ_EXPRESSION      | Yes      | Filter expression for VPCs                                               | `.IsDefault == false and .Tags != null`               | `.Tags[]           |
| `filter_vpcs_OutputMethod`                 | STRING             | Yes      | Return all or first result                                               | `ALL`                                                 | `ALL`, `FIRST` |
| `fetch_ec2_in_vpcs_RequestConfigFile`      | HTTP_CONFIG (TOML) | Yes      | AWS EC2 DescribeInstances API configuration for VPC filtering            | See configuration file                                  | N/A                |
| `extract_security_groups_JQTransform`      | JQ_EXPRESSION      | Yes      | JQ expression to extract security group IDs                              | `[.Reservations[].Instances[].SecurityGroups[].GroupId] | unique             |
| `extract_security_groups_OutputMethod`     | STRING             | Yes      | Return all or first result                                               | `ALL`                                                 | `ALL`, `FIRST` |
| `fetch_all_ec2_with_sgs_RequestConfigFile` | HTTP_CONFIG (TOML) | Yes      | AWS EC2 DescribeInstances API configuration for security group filtering | See configuration file                                  | N/A                |
| `generate_report_JQTransform`              | JQ_EXPRESSION      | Yes      | JQ transformation for compliance report generation                       | See transformation expression                           | N/A                |
| `generate_report_OutputMethod`             | STRING             | Yes      | Return all or first result                                               | `ALL`                                                 | `ALL`, `FIRST` |

### Input Details

#### 1. fetch_vpcs_RequestConfigFile

**Format:** TOML
**Purpose:** Configures AWS EC2 API call to fetch all VPCs

**Sample Configuration:**

```toml
[Variables]
Action = "DescribeVpcs"
Version = "2016-11-15"

[Request]
URL = "https://ec2.amazonaws.com/"
Method = "GET"
ContentType = "application/x-www-form-urlencoded"
CredentialType = "AWSSignature"
TimeOut = 30

[Request.Params]
Action = "<<Action>>"
Version = "<<Version>>"
```

#### 2. filter_vpcs_JQFilter

**Format:** JQ Expression
**Purpose:** Filters VPCs based on criteria

**Examples:**

- Filter non-default VPCs with tags: `.IsDefault == false and .Tags != null`
- Filter by specific tag: `.Tags[] | select(.Key == "Environment" and .Value == "Production")`
- Filter by CIDR: `.CidrBlock | startswith("10.0")`

#### 3. fetch_ec2_in_vpcs_RequestConfigFile

**Format:** TOML
**Purpose:** Fetches EC2 instances within filtered VPCs using InputFile iteration

**Key Configuration:**

```toml
[Request.Params]
Action = "DescribeInstances"
"Filter.1.Name" = "vpc-id"
"Filter.1.Values.1" = "<<inputfile.vpcId>>"
```

#### 4. extract_security_groups_JQTransform

**Format:** JQ Expression
**Purpose:** Extracts unique security group IDs from EC2 instances

**Expression:**

```jq
[.Reservations[].Instances[].SecurityGroups[].GroupId] | unique | map({GroupId: .})
```

#### 5. fetch_all_ec2_with_sgs_RequestConfigFile

**Format:** TOML
**Purpose:** Finds ALL EC2 instances across the account that use the identified security groups

**Key Configuration:**

```toml
[Request.Params]
Action = "DescribeInstances"
"Filter.1.Name" = "instance.group-id"
"Filter.1.Values.1" = "<<inputfile.GroupId>>"
```

#### 6. generate_report_JQTransform

**Format:** JQ Expression
**Purpose:** Transforms EC2 data into ComplianceCow standard compliance format

**Output Fields:**

- System, Source, ResourceID, ResourceName, ResourceType
- ResourceLocation, ResourceTags, VpcId, SecurityGroups
- PrivateIpAddress, PublicIpAddress, InstanceState
- ValidationStatusCode, ValidationStatusNotes
- ComplianceStatus, ComplianceStatusReason
- EvaluatedTime, UserAction, ActionStatus, ActionResponseURL

---

## Tasks

### Task 1: fetch_vpcs

**Name:** ExecuteHttpRequestV2
**Alias:** fetch_vpcs
**Application Type:** httprequest

**Purpose:** Fetch all VPCs from AWS account using EC2 DescribeVpcs API

**Inputs:**

- RequestConfigFile: AWS API configuration

**Outputs:**

- OutputFile: JSON array of all VPCs in the account
- LogFile: Execution log
- CompliancePCT_, ComplianceStatus_: Task status

**Processing Logic:**

- Calls AWS EC2 DescribeVpcs API
- Uses AWS Signature V4 authentication
- Returns complete VPC inventory

---

### Task 2: filter_vpcs

**Name:** FilterDataWithJQ
**Alias:** filter_vpcs
**Application Type:** nocredapp

**Purpose:** Filter VPCs based on user-defined criteria (tags or names)

**Inputs:**

- InputFile: VPC data from Task 1
- JQFilter: Filter expression (e.g., `.IsDefault == false and .Tags != null`)
- OutputMethod: ALL (return all matching VPCs)

**Outputs:**

- FilteredFile: VPCs matching the filter criteria
- LogFile: Execution log
- CompliancePCT_, ComplianceStatus_: Task status

**Processing Logic:**

- Evaluates JQ filter against each VPC record
- Returns only VPCs that match the criteria
- Excludes default VPCs without tags by default

---

### Task 3: fetch_ec2_in_vpcs

**Name:** ExecuteHttpRequestV2
**Alias:** fetch_ec2_in_vpcs
**Application Type:** httprequest

**Purpose:** List EC2 instances within the filtered VPCs

**Inputs:**

- RequestConfigFile: AWS API configuration for EC2 instances
- InputFile: Filtered VPCs from Task 2

**Outputs:**

- OutputFile: JSON array of EC2 instances in filtered VPCs
- LogFile: Execution log
- CompliancePCT_, ComplianceStatus_: Task status

**Processing Logic:**

- Iterates over each filtered VPC
- Calls AWS EC2 DescribeInstances with VPC ID filter
- Aggregates all EC2 instances from filtered VPCs

---

### Task 4: extract_security_groups

**Name:** TransformDataWithJQ
**Alias:** extract_security_groups
**Application Type:** nocredapp

**Purpose:** Extract unique security group IDs from EC2 instances

**Inputs:**

- InputFile: EC2 instances from Task 3
- JQTransform: Expression to extract and deduplicate security groups
- OutputMethod: ALL (return all unique security groups)

**Outputs:**

- TransformedFile: Array of unique security group IDs
- LogFile: Execution log
- CompliancePCT_, ComplianceStatus_: Task status

**Processing Logic:**

- Navigates through EC2 instance data structure
- Extracts all security group IDs
- Removes duplicates using `unique`
- Formats as array of objects with GroupId field

---

### Task 5: fetch_all_ec2_with_sgs

**Name:** ExecuteHttpRequestV2
**Alias:** fetch_all_ec2_with_sgs
**Application Type:** httprequest

**Purpose:** Find all EC2 instances sharing the identified security groups

**Inputs:**

- RequestConfigFile: AWS API configuration for security group filtering
- InputFile: Unique security groups from Task 4

**Outputs:**

- OutputFile: Complete population of EC2 instances using those security groups
- LogFile: Execution log
- CompliancePCT_, ComplianceStatus_: Task status

**Processing Logic:**

- Iterates over each unique security group
- Calls AWS EC2 DescribeInstances with security group filter
- Returns ALL EC2 instances across the account that use those security groups
- This discovers instances beyond the originally filtered VPCs

---

### Task 6: generate_report

**Name:** TransformDataWithJQ
**Alias:** generate_report
**Application Type:** nocredapp

**Purpose:** Generate standard compliance report

**Inputs:**

- InputFile: Complete EC2 instance data from Task 5
- JQTransform: Transformation to ComplianceCow standard schema
- OutputMethod: ALL (return all transformed records)

**Outputs:**

- TransformedFile: Standard compliance report
- LogFile: Execution log
- CompliancePCT_, ComplianceStatus_: Overall compliance metrics

**Processing Logic:**

- Transforms EC2 data to standard compliance schema
- Adds system identification (AWS, ComplianceCow)
- Includes resource details, VPC info, security groups
- Generates validation codes and compliance status
- Adds evaluation timestamp

---

## Outputs

| Output Name                   | Type   | Description                                                                                        | Format    |
| ----------------------------- | ------ | -------------------------------------------------------------------------------------------------- | --------- |
| `ComplianceReport`          | FILE   | Standard compliance report with EC2 instance details, VPC information, and security group analysis | JSON      |
| `ExtendedData_EC2Instances` | FILE   | Complete raw EC2 instance data from AWS API for audit trail                                        | JSON      |
| `CompliancePCT_`            | INT    | Compliance percentage (always 100% for discovery rules)                                            | Integer   |
| `ComplianceStatus_`         | STRING | Overall compliance status                                                                          | COMPLIANT |
| `LogFile`                   | FILE   | Execution log file with errors and status                                                          | JSON      |

### Output Details

#### ComplianceReport (Standard Schema)

**Description:** Standardized compliance report following ComplianceCow schema

**Sample Structure:**

```json
[
  {
    "System": "aws",
    "Source": "compliancecow",
    "ResourceID": "i-0123456789abcdef0",
    "ResourceName": "my-ec2-instance",
    "ResourceType": "EC2Instance",
    "ResourceLocation": "us-east-1a",
    "ResourceTags": "Environment=Production, Application=WebServer",
    "VpcId": "vpc-abc123",
    "SecurityGroups": "sg-123456, sg-789012",
    "PrivateIpAddress": "10.0.1.100",
    "PublicIpAddress": "54.123.45.67",
    "InstanceState": "running",
    "ValidationStatusCode": "INST_IN_VPC_WITH_SG",
    "ValidationStatusNotes": "Instance found in filtered VPC with identified security group",
    "ComplianceStatus": "COMPLIANT",
    "ComplianceStatusReason": "EC2 instance is part of the analyzed VPC and uses the identified security groups",
    "EvaluatedTime": "2026-04-08T00:52:00Z",
    "UserAction": "",
    "ActionStatus": "",
    "ActionResponseURL": ""
  }
]
```

#### ExtendedData_EC2Instances (Extended Schema)

**Description:** Complete raw AWS EC2 API response preserving all fields

**Purpose:**

- Complete audit trail
- Detailed EC2 instance information
- Raw AWS API response for troubleshooting
- Additional fields not in standard schema

---

## Configuration

### Application Type and Environment

- **Application Type:** httprequest
- **Environment:** logical
- **Execution Level:** app

### Authentication Requirements

**AWS Credentials Required:**

- AWS Access Key ID
- AWS Secret Access Key

**Permissions Needed:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeInstances"
      ],
      "Resource": "*"
    }
  ]
}
```

### System Prerequisites

- AWS account access
- Valid AWS IAM credentials with EC2 read permissions
- Network access to AWS EC2 API endpoints

---

## Usage Examples

### Basic Usage - All Non-Default Tagged VPCs

**Filter Configuration:**

```jq
.IsDefault == false and .Tags != null
```

**Expected Result:**

- Analyzes all non-default VPCs that have tags
- Lists EC2 instances within those VPCs
- Identifies security groups
- Finds all EC2s across account using those security groups

---

### Advanced - Production Environment VPCs

**Filter Configuration:**

```jq
.Tags != null and (.Tags[] | select(.Key == "Environment" and .Value == "Production"))
```

**Use Case:**

- Target only production-tagged VPCs
- Analyze security group usage in production
- Audit production EC2 instance associations

---

### Network-Specific Analysis

**Filter Configuration:**

```jq
.CidrBlock | startswith("10.0") and .Tags != null
```

**Use Case:**

- Filter VPCs by CIDR block range
- Analyze specific network segments
- Security posture for particular subnets

---

## I/O Mapping

### Complete Data Flow

```yaml
# Rule Input → Task 1
fetch_vpcs.Input.RequestConfigFile := *.Input.fetch_vpcs_RequestConfigFile

# Task 1 → Task 2
filter_vpcs.Input.InputFile := fetch_vpcs.Output.OutputFile
filter_vpcs.Input.JQFilter := *.Input.filter_vpcs_JQFilter
filter_vpcs.Input.OutputMethod := *.Input.filter_vpcs_OutputMethod

# Task 2 → Task 3
fetch_ec2_in_vpcs.Input.RequestConfigFile := *.Input.fetch_ec2_in_vpcs_RequestConfigFile
fetch_ec2_in_vpcs.Input.InputFile := filter_vpcs.Output.FilteredFile

# Task 3 → Task 4
extract_security_groups.Input.InputFile := fetch_ec2_in_vpcs.Output.OutputFile
extract_security_groups.Input.JQTransform := *.Input.extract_security_groups_JQTransform
extract_security_groups.Input.OutputMethod := *.Input.extract_security_groups_OutputMethod

# Task 4 → Task 5
fetch_all_ec2_with_sgs.Input.RequestConfigFile := *.Input.fetch_all_ec2_with_sgs_RequestConfigFile
fetch_all_ec2_with_sgs.Input.InputFile := extract_security_groups.Output.TransformedFile

# Task 5 → Task 6
generate_report.Input.InputFile := fetch_all_ec2_with_sgs.Output.OutputFile
generate_report.Input.JQTransform := *.Input.generate_report_JQTransform
generate_report.Input.OutputMethod := *.Input.generate_report_OutputMethod

# Task 6 → Rule Outputs (Standard + Extended)
*.Output.ComplianceReport := generate_report.Output.TransformedFile
*.Output.ExtendedData_EC2Instances := fetch_all_ec2_with_sgs.Output.OutputFile
*.Output.CompliancePCT_ := generate_report.Output.CompliancePCT_
*.Output.ComplianceStatus_ := generate_report.Output.ComplianceStatus_
*.Output.LogFile := generate_report.Output.LogFile
```

### Data Transformation Stages

| Stage | Input           | Transformation             | Output                 |
| ----- | --------------- | -------------------------- | ---------------------- |
| 1     | AWS Account     | DescribeVpcs API           | All VPCs               |
| 2     | All VPCs        | JQ Filter                  | Filtered VPCs          |
| 3     | Filtered VPCs   | DescribeInstances (by VPC) | EC2s in VPCs           |
| 4     | EC2s in VPCs    | Extract & Deduplicate      | Unique Security Groups |
| 5     | Security Groups | DescribeInstances (by SG)  | All EC2s with SGs      |
| 6     | All EC2s        | Transform to Schema        | Compliance Report      |

---

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: No VPCs Returned

**Symptom:** Empty output from filter_vpcs task

**Possible Causes:**

- Filter criteria too restrictive
- All VPCs are default VPCs
- No VPCs have tags

**Solution:**

- Adjust JQ filter expression
- Use `.IsDefault == false` without tag requirement
- Verify VPCs exist in AWS account

---

#### Issue 2: Authentication Errors

**Symptom:** AWS API returns 403 Forbidden or authentication errors

**Possible Causes:**

- Invalid AWS credentials
- Insufficient IAM permissions
- Expired access keys

**Solution:**

- Verify AWS Access Key ID and Secret Access Key
- Check IAM policy includes `ec2:DescribeVpcs` and `ec2:DescribeInstances`
- Rotate and update credentials if expired

---

#### Issue 3: Empty EC2 Instance List

**Symptom:** No EC2 instances found in filtered VPCs

**Possible Causes:**

- Filtered VPCs contain no EC2 instances
- EC2 instances are terminated
- Region mismatch

**Solution:**

- Verify EC2 instances exist in the filtered VPCs
- Check instance states (running, stopped, etc.)
- Ensure API calls target correct AWS region

---

#### Issue 4: Performance Issues

**Symptom:** Rule execution takes very long time

**Possible Causes:**

- Large number of VPCs or EC2 instances
- Low MaxWorkers setting
- API rate limiting

**Solution:**

- Increase MaxWorkers in RequestConfigFile (up to 20)
- Add more specific filters to reduce data volume
- Implement pagination if hitting API limits

---

## Version History

| Version | Date       | Changes                                                     | Migration Notes |
| ------- | ---------- | ----------------------------------------------------------- | --------------- |
| 1.0.0   | 2026-04-08 | Initial release                                             | N/A             |
|         |            | - 6-task workflow for VPC and security group analysis       |                 |
|         |            | - Support for VPC filtering by tags and attributes          |                 |
|         |            | - Security group extraction and cross-account EC2 discovery |                 |
|         |            | - Standard + Extended output schema                         |                 |
|         |            | - AWS Signature V4 authentication                           |                 |

---

## Authors

**Primary Author(s):**

- Jesus Fidalgo
- Mosi Platt
- Carlos Victoria
- Megha Shah
- Raj Krishnamurthy

**Contributors:**

- Shradha Krish
- Ram Manavalan
- Arul G

## References

### AWS Documentation

- [AWS EC2 DescribeVpcs API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVpcs.html)
- [AWS EC2 DescribeInstances API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html)
- [AWS Signature Version 4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
- [AWS EC2 Security Groups](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html)
- ### Compliance Frameworks
- IT Asset Management (ITAM) best practices
- Configuration Management Database (CMDB) standards
- Cloud Asset Inventory compliance requirements

---



## Changelog

All notable changes to this rule will be documented in this section.

**[1.0.0] - 2026-04-08**

- Initial release

**Last Updated:** 2026-04-08
**Rule Status:** ACTIVE
**Maintained By:** ComplianceCow Team
