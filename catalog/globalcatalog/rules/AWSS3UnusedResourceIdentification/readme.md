# README for AWSS3UnusedResourceIdentification

## Purpose of Rule

The purpose of this rule is to identify unused S3 resources by analyzing bucket access patterns from CloudTrail logs. It classifies S3 buckets as non-compliant if they have not been accessed for more than 45 days. The rule performs the following steps:

1. Fetches all S3 buckets from the configured AWS accounts.
2. Retrieves the list of IAM users with access permissions to these buckets.
3. Retrieves and parses CloudTrail audit logs to detect any read/write S3 operations.
4. Calculates the number of days since each S3 bucket was last accessed.
5. Marks buckets as NON_COMPLIANT if they have been inactive for more than 45 days, or COMPLIANT if they have been actively accessed within that period.
6. Generates a comprehensive compliance report mapping inactive S3 resources.

## Inputs with Explanation

The rule requires the following inputs:

1. **fetch_s3_buckets_RequestConfigFile (HTTP_CONFIG)**:
   - **Description**: Configuration file in TOML format specifying request details to fetch S3 buckets from AWS accounts. Available in the `TaskInputs` folder.
   - **Format**: TOML
   - **Required**: Yes

2. **fetch_iam_users_RequestConfigFile (HTTP_CONFIG)**:
   - **Description**: Configuration file in TOML format specifying request details to fetch IAM users with S3 access permissions. Available in the `TaskInputs` folder.
   - **Format**: TOML
   - **Required**: Yes

3. **fetch_cloudtrail_logs_RequestConfigFile (HTTP_CONFIG)**:
   - **Description**: Configuration file in TOML format specifying request details to query AWS CloudTrail logs for S3 bucket access history. Available in the `TaskInputs` folder.
   - **Format**: TOML
   - **Required**: Yes

4. **analyze_access_JQTransform (JQ_EXPRESSION)**:
   - **Description**: JQ expression that maps raw CloudTrail log events into normalized records specifying bucket names, event sources, timestamps, and calculates `DaysSinceAccess`.
   - **Required**: Yes

5. **analyze_access_OutputMethod (STRING)**:
   - **Description**: Mode to output parsed access event records.
   - **Default**: ALL
   - **Required**: Yes

6. **determine_compliance_JQTransform (JQ_EXPRESSION)**:
   - **Description**: JQ expression that evaluates each bucket's activity against the 45-day threshold to compute compliance states and status reasoning.
   - **Required**: Yes

7. **determine_compliance_OutputMethod (STRING)**:
   - **Description**: Mode to output finalized compliance records.
   - **Default**: ALL
   - **Required**: Yes

## Outputs with Explanation

The task generates the following outputs after processing:

1. **S3UnusedResourceReport (FILE)**:
   * **Description**: Complete structured JSON file containing standardized compliance records for S3 unused resources.
   * **Required**: Yes

2. **ExtendedData_S3AccessLogs (FILE)**:
   * **Description**: Detailed report containing the full combined dataset of raw S3 access logs and compliance statuses.
   * **Required**: Yes

3. **LogFile (FILE)**:
   * **Description**: Error log file containing details of any failures or logs recorded during rule execution.
   * **Required**: Yes

4. **CompliancePCT_ (INT)**:
   * **Description**: Calculated compliance percentage value representing the percentage of compliant (active) S3 buckets.

5. **ComplianceStatus_ (STRING)**:
   * **Description**: Overall compliance evaluation status for the rule execution.

## Compliance Truth Table

| Days Since Last Access | ValidationStatusCode | ComplianceStatus | ComplianceStatusReason | ValidationStatusNotes |
|:---|:---|:---|:---|:---|
| `> 45` days | S3_NO_ACC_45D | **NON_COMPLIANT** | S3 bucket not accessed for more than 45 days | Bucket has been inactive for {DaysSinceAccess} days |
| `<= 45` days | S3_ACC_OK | **COMPLIANT** | S3 bucket accessed within 45 days | Bucket actively used |

## Sample Output Structure

```json
{
  "BucketName": "company-archive-logs",
  "UserIdentity": "backup-agent",
  "EventName": "GetObject",
  "EventTime": "2026-05-10T14:30:00Z",
  "EventSource": "s3.amazonaws.com",
  "LastAccessDate": "2026-05-10T14:30:00Z",
  "DaysSinceAccess": 94,
  "ComplianceStatus": "NON_COMPLIANT",
  "ComplianceStatusReason": "S3 bucket not accessed for more than 45 days",
  "ValidationStatusCode": "S3_NO_ACC_45D",
  "ValidationStatusNotes": "Bucket has been inactive for 94 days"
}
```
