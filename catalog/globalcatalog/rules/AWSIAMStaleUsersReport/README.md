# README for AWSIAMStaleUsersReport

## Purpose of Rule

The purpose of this rule is to fetch AWS IAM users and identify stale users who haven't used their password in more than 90 days. It performs the following steps:

1. Fetches all AWS IAM users using the ListUsers API
2. Filters users whose password was last used more than 90 days ago or never used
3. Transforms the data into a standardized compliance report format
4. Converts the final output to CSV format for easy analysis and reporting

## Inputs with Explanation

The rule requires the following inputs:

1. **RequestConfigFile (HTTP_CONFIG)**:
   - **Description**: Configuration file in TOML format that defines the HTTP request parameters for fetching AWS IAM users via the ListUsers API. This includes AWS API endpoint, authentication credentials (AWS Access Key ID and Secret Access Key), request headers, and API-specific parameters.
   - **Format**: TOML
   - **Required**: Yes

2. **JQFilter (JQ_EXPRESSION)**:
   - **Description**: A JQ expression that filters the raw AWS IAM user data to identify stale users. This filter selects only users whose password has never been used (PasswordLastUsed is null) or was last used more than 90 days ago.
   - **Required**: Yes
   - **Default Expression**: `.[].ListUsersResponse.ListUsersResult.Users.member[] | select(.PasswordLastUsed == null or ((now - (.PasswordLastUsed | fromdateiso8601)) / 86400) > 90)`
   - **Filter Logic**:
     - Navigates through the AWS API response structure
     - Selects users where PasswordLastUsed is null (never used)
     - OR selects users where password was last used more than 90 days ago
     - Calculates days by converting ISO date to epoch time and dividing difference by 86400 (seconds in a day)

3. **JQTransform (JQ_EXPRESSION)**:
   - **Description**: A JQ expression that transforms the filtered AWS IAM user data into a standardized ComplianceCow format. This expression extracts and maps AWS user attributes to compliance fields, calculates staleness metrics, and generates compliance classifications.
   - **Required**: Yes
   - **Default Expression Structure**:
     - **System**: Set to "aws" to identify the source system
     - **Source**: Set to "compliancecow" to identify the compliance platform
     - **ResourceID**: AWS user's ARN (Amazon Resource Name)
     - **ResourceName**: IAM username
     - **ResourceType**: Set to "IAMUser" for all records
     - **ResourceLocation**: Extracted from ARN (AWS region)
     - **ResourceTags**: Array of tags associated with the IAM user
     - **UserName**: IAM username
     - **PasswordLastUsed**: ISO timestamp of when password was last used (null if never used)
     - **DaysSinceLastUsed**: Calculated number of days since password was last used
     - **IsStale**: Boolean indicating if user is stale (true if never used or >90 days)
     - **ValidationStatusCode**: 
       - "PASS_ACCT_STALE" if password not used in >90 days or never used
       - "FAIL_ACCT_ACTV" if password used within 90 days
     - **ValidationStatusNotes**: Detailed message about password usage status
     - **ComplianceStatus**: "NON_COMPLIANT" for stale users, "COMPLIANT" for active users
     - **ComplianceStatusReason**: Explanation of compliance status
     - **EvaluatedTime**: Timestamp of when the evaluation was performed
     - **UserAction**: Empty field for future action tracking
     - **ActionStatus**: Empty field for action status tracking
     - **ActionResponseURL**: Empty field for action response links

4. **OutputMethod (STRING)**:
   - **Description**: Specifies how the transformed data should be output. "ALL" outputs all transformed records, while "FIRST" outputs only the first record.
   - **Default**: ALL
   - **Required**: Yes

5. **OutputFileFormat (STRING)**:
   - **Description**: Specifies the final output file format for the stale users report. The report will be converted to this format for easy consumption and analysis.
   - **Default**: CSV
   - **Required**: Yes
   - **Example**: `"CSV"`

## Outputs with Explanation

The task generates the following outputs after processing:

1. **CompliancePCT_ (INT)**:
   - **Description**: A calculated compliance percentage value indicating what percentage of AWS IAM users are active (not stale). This metric helps assess the overall health of IAM user accounts in the organization.
   - **Calculation**: (Number of active users / Total number of users) × 100

2. **ComplianceStatus_ (STRING)**:
   - **Description**: A status indicator showing the overall compliance level for IAM user activity. Possible values include "COMPLIANT" or "NON_COMPLIANT" based on the proportion of stale users in the organization.

3. **LogFile (FILE)**:
   - **Description**: If any errors occur during execution (e.g., AWS API authentication failures, connection issues, data transformation errors, invalid responses), an error log is generated in JSON format. This file contains detailed error messages, timestamps, affected records, and troubleshooting information for each stage of the workflow.

4. **StaleUsersReport (FILE)**:
   - **Description**: A comprehensive CSV file containing the final stale IAM users report. This report includes:
     - User identification details (ARN, username)
     - Password usage information (last used timestamp, days since last use)
     - Staleness classification (IsStale flag)
     - Compliance status and detailed reasoning
     - Validation status codes and notes
     - Resource metadata (location, tags)
     - Evaluation timestamp for audit purposes
     - Empty action fields for tracking remediation efforts
   
   The data is fully standardized in CSV format, making it easy to identify stale users requiring deactivation or password reset and track overall organizational IAM hygiene.

## Compliance Truth Table

| Password Last Used | Days Since Last Used | IsStale | ValidationStatusCode | ComplianceStatus | ComplianceStatusReason |
|-------------------|---------------------|---------|---------------------|------------------|------------------------|
| null (never used) | null | true | PASS_ACCT_STALE | **NON_COMPLIANT** | Stale user account detected - password not used in over 90 days |
| > 90 days ago | > 90 | true | PASS_ACCT_STALE | **NON_COMPLIANT** | Stale user account detected - password not used in over 90 days |
| ≤ 90 days ago | ≤ 90 | false | FAIL_ACCT_ACTV | **COMPLIANT** | Active user account - password used within compliance period |


## Sample Output Structure
```json
{
  "System": "aws",
  "Source": "compliancecow",
  "ResourceID": "arn:aws:iam::123456789012:user/john.doe",
  "ResourceName": "john.doe",
  "ResourceType": "User",
  "ResourceLocation": "",
  "ResourceTags": [],
  "UserName": "john.doe",
  "PasswordLastUsed": "2024-06-15T10:30:00Z",
  "DaysSinceLastUsed": 149,
  "IsStale": true,
  "ValidationStatusCode": "PASS_ACCT_STALE",
  "ValidationStatusNotes": "User has never used password - considered stale",
  "ComplianceStatus": "NON_COMPLIANT",
  "ComplianceStatusReason": "Stale user account detected - password not used in over 90 days",
  "EvaluatedTime": "2025-11-11T10:30:45Z",
  "UserAction": "",
  "ActionStatus": "",
  "ActionResponseURL": ""
}
```