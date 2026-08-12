# README for AWSS3BucketEncryptionCompliance

## Purpose of Rule

The purpose of this rule is to validate that all S3 buckets in your AWS accounts have server-side encryption enabled for data security compliance. It performs the following steps:

1. Fetches all S3 buckets from the configured AWS accounts.
2. Checks the encryption configuration for each bucket using the AWS S3 API (`GET /?encryption`).
3. Classifies each bucket as COMPLIANT (encryption enabled) or NON_COMPLIANT (encryption missing).
4. Generates a comprehensive compliance report in CSV and JSON formats.

## Inputs with Explanation

The rule requires the following inputs:
1. **fetch_buckets_RequestConfigFile (HTTP_CONFIG)**:
   - **Description**: Configuration file in TOML format specifying the AWS signature-authenticated request details to list all S3 buckets in the AWS account. Available in the `TaskInputs` folder.
   - **Format**: TOML
   - **Required**: Yes

2. **fetch_buckets_ResponseConfigFile (HTTP_CONFIG)**:
   - **Description**: Configuration file in TOML format specifying response mapping rules to extract the names and creation dates of the S3 buckets. Available in the `TaskInputs` folder.
   - **Format**: TOML
   - **Required**: Yes

3. **check_encryption_RequestConfigFile (HTTP_CONFIG)**:
   - **Description**: Configuration file in TOML format specifying request details to query server-side encryption settings for each individual S3 bucket. Available in the `TaskInputs` folder.
   - **Format**: TOML
   - **Required**: Yes

4. **check_encryption_ResponseConfigFile (HTTP_CONFIG)**:
   - **Description**: Configuration file in TOML format specifying response parsing rules to extract status codes and encryption settings (SSEAlgorithm, BucketKeyEnabled) for each bucket. Available in the `TaskInputs` folder.
   - **Format**: TOML
   - **Required**: Yes

5. **JQTransform (JQ_EXPRESSION)**:
   - **Description**: A JQ expression that parses the API execution outputs and maps them into a standardized compliance schema.
   - **Required**: Yes
   - **Default Expression Structure**:
     - **System**: Set to `"aws"` to identify the source cloud system.
     - **Source**: Set to `"compliancecow"` to identify the compliance platform.
     - **ResourceID**: The name of the S3 bucket (`.BucketName`).
     - **ResourceName**: The name of the S3 bucket (`.BucketName`).
     - **ResourceType**: Set to `"S3Bucket"`.
     - **ResourceLocation**: Set to `"global"`.
     - **ResourceTags**: Empty string placeholder.
     - **ResourceURL**: Direct link to the S3 bucket (`"https://" + .BucketName + ".s3.amazonaws.com"`).
     - **EncryptionEnabled**: Boolean string (`"true"` if encryption status is HTTP 200, `"false"` otherwise).
     - **EncryptionAlgorithm**: The algorithm used (`.EncryptionType` or `"None"`).
     - **KMSKeyID**: The KMS Master Key ID if KMS is used, otherwise `"N/A"`.
     - **ValidationStatusCode**: `"ENCR_ENBL_S3BK"` if compliant, `"ENCR_MISS_S3BK"` if non-compliant.
     - **ValidationStatusNotes**: Text description indicating encryption status.
     - **ComplianceStatus**: `"COMPLIANT"` if encryption is enabled, `"NON_COMPLIANT"` if disabled/missing.
     - **ComplianceStatusReason**: Explanatory text for the compliance status.
     - **EvaluatedTime**: Timestamp of the audit run.

6. **OutputMethod (STRING)**:
   - **Description**: Mode to output transformed records. "ALL" outputs all records.
   - **Default**: ALL
   - **Required**: Yes

7. **OutputFileFormat (STRING)**:
   - **Description**: File format for the exported compliance report.
   - **Default**: CSV
   - **Allowed Values**: JSON, CSV, PARQUET, YAML, TOML, XLSX
   - **Required**: Yes

8. **OutputFileName (STRING)**:
   - **Description**: The prefix filename for the output compliance reports.
   - **Default**: S3BucketEncryptionComplianceReport
   - **Required**: Yes

## Outputs with Explanation

The task generates the following outputs after processing:

1. **S3BucketEncryptionComplianceReportCSV (FILE)**:
   * **Description**: Final compliance report in CSV format containing all compliance and metadata columns, compatible with spreadsheet processors like Excel.
   * **Required**: Yes

2. **S3BucketEncryptionComplianceReportJSON (FILE)**:
   * **Description**: Raw JSON file listing complete, structured records of the compliance evaluation for each bucket.
   * **Required**: Yes

3. **LogFile (FILE)**:
   * **Description**: File containing logs and details about any errors encountered during task execution.
   * **Required**: Yes

4. **CompliancePCT_ (INT)**:
   * **Description**: A calculated compliance percentage value representing the ratio of compliant buckets to total audited buckets.

5. **ComplianceStatus_ (STRING)**:
   * **Description**: The overall status indicator showing whether compliance criteria are met (e.g., COMPLIANT or NON_COMPLIANT).

## Compliance Truth Table

| S3 GET /?encryption Response Status | Encryption Enabled | ValidationStatusCode | ComplianceStatus | ComplianceStatusReason |
|:---|:---|:---|:---|:---|
| `200` (OK) | `true` | ENCR_ENBL_S3BK | **COMPLIANT** | S3 bucket has server-side encryption enabled |
| Any other status / Error | `false` | ENCR_MISS_S3BK | **NON_COMPLIANT** | S3 bucket does not have encryption enabled |

## Sample Output Structure

```json
{
  "System": "aws",
  "Source": "compliancecow",
  "ResourceID": "my-compliant-s3-bucket-123456789012",
  "ResourceName": "my-compliant-s3-bucket-123456789012",
  "ResourceType": "S3Bucket",
  "ResourceLocation": "global",
  "ResourceTags": "",
  "ResourceURL": "https://my-compliant-s3-bucket-123456789012.s3.amazonaws.com",
  "EncryptionEnabled": "true",
  "EncryptionAlgorithm": "AES256",
  "KMSKeyID": "N/A",
  "BucketKeyEnabled": "false",
  "BucketName": "my-compliant-s3-bucket-123456789012",
  "CreationDate": "2026-01-15T08:00:00.000Z",
  "EncryptionType": "AES256",
  "KMSMasterKeyID": "",
  "StatusCode": "200",
  "ValidationStatusCode": "ENCR_ENBL_S3BK",
  "ValidationStatusNotes": "Encryption enabled with AES256",
  "ComplianceStatus": "COMPLIANT",
  "ComplianceStatusReason": "S3 bucket has server-side encryption enabled",
  "EvaluatedTime": "2026-08-12T12:00:00Z",
  "UserAction": "",
  "ActionStatus": "",
  "ActionResponseURL": ""
}
```

