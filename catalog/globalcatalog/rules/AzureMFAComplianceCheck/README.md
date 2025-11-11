# README for AzureMFAComplianceCheck

## Purpose of Rule

The purpose of this rule is to check Azure Active Directory users for Multi-Factor Authentication (MFA) enablement compliance. It performs the following steps:

1. Fetches Azure Active Directory user data including MFA registration status
2. Transforms and analyzes MFA status for each user
3. Classifies users as COMPLIANT (MFA enabled) or NON_COMPLIANT (MFA disabled)
4. Generates a comprehensive compliance report with detailed MFA status information

## Inputs with Explanation

The rule requires the following inputs:

1. **AzureRequestConfigFile (HTTP_CONFIG)**:
   - **Description**: Configuration file in TOML format that defines the HTTP request parameters for retrieving Azure Active Directory user data. This includes Microsoft Graph API endpoint, authentication tokens (using OAuth 2.0 or app credentials), request headers, and query parameters for fetching user MFA registration details.
   - **Format**: TOML
   - **Required**: Yes

2. **AzureResponseConfigFile (HTTP_CONFIG)**:
   - **Description**: Configuration file in TOML format that defines how to process and parse the HTTP response from Azure Active Directory. This includes response mapping, data extraction rules, pagination handling.
   - **Format**: TOML
   - **Required**: Yes

3. **JQTransform (JQ_EXPRESSION)**:
   - **Description**: A JQ expression that transforms the raw Azure user data into a standardized compliance report format. This expression extracts and maps Azure user attributes to compliance fields, evaluates MFA status, and generates compliance classifications.
   - **Required**: Yes
   - **Default Expression Structure**:
     - **System**: Set to "azure" to identify the source system
     - **Source**: Set to "compliancecow" to identify the compliance platform
     - **ResourceID**: Azure user's unique identifier (.id)
     - **ResourceName**: User's display name (.userDisplayName)
     - **ResourceType**: Set to "User" for all records
     - **ResourceLocation**: Set to "N/A" as Azure users don't have a specific location
     - **ResourceTags**: Empty array for additional tags
     - **ResourceURL**: Direct link to user's Azure portal profile
     - **UserPrincipalName**: User's principal name (.userPrincipalName)
     - **AccountEnabled**: Set to true for active accounts
     - **MFAMethods**: Array of registered MFA methods (.methodsRegistered)
     - **MFAEnabled**: Boolean indicating if MFA is registered (.isMfaRegistered)
     - **ValidationStatusCode**: "MFA_ENBL" if MFA is enabled, "MFA_DSBL" if disabled
     - **ValidationStatusNotes**: Detailed message about MFA status including number of methods or risk warning
     - **ComplianceStatus**: "COMPLIANT" if MFA is enabled, "NON_COMPLIANT" if disabled
     - **ComplianceStatusReason**: Explanation of compliance status
     - **EvaluatedTime**: Timestamp of when the evaluation was performed
     - **UserAction**: Empty field for future action tracking
     - **ActionStatus**: Empty field for action status tracking
     - **ActionResponseURL**: Empty field for action response links

4. **OutputMethod (STRING)**:
   - **Description**: Specifies how the transformed data should be output. "ALL" outputs all transformed records, while "FIRST" outputs only the first record.
   - **Default**: ALL
   - **Required**: Yes
   - **Allowed Values**: ALL, FIRST

5. **ProceedIfLogExists (boolean)**:
   - **Description**: A flag that determines whether the rule should proceed with execution if a log file is passed from a previous rule or task. Set to `true` to continue execution even if logs are present, or `false` to stop execution when logs exist.
   - **Default**: false
   - **Required**: Yes

6. **ProceedIfErrorExists (boolean)**:
   - **Description**: A flag that determines whether the rule should continue execution if an error occurs at the current rule level. Set to `true` to proceed despite errors, or `false` to stop the rule execution when errors are encountered.
   - **Default**: false
   - **Required**: Yes

## Outputs with Explanation

The task generates the following outputs after processing:

1. **CompliancePCT_ (INT)**:
   - **Description**: A calculated compliance percentage value indicating what percentage of Azure Active Directory users have MFA enabled. This metric helps assess overall organizational compliance with MFA security policies.
   - **Calculation**: (Number of users with MFA enabled / Total number of users) × 100

2. **ComplianceStatus_ (STRING)**:
   - **Description**: A status indicator showing the overall compliance level for MFA requirements across all Azure users. Possible values include "COMPLIANT" or "NON_COMPLIANT" based on defined organizational thresholds.

3. **LogFile (FILE)**:
   - **Description**: If any errors occur during execution (e.g., API authentication failures, connection issues, data transformation errors, invalid responses), an error log is generated in JSON format. This file contains detailed error messages, timestamps, affected records, and troubleshooting information for each stage of the workflow.

4. **AzureMFAComplianceReport (FILE)**:
   - **Description**: A comprehensive JSON file containing the final MFA compliance report for all Azure Active Directory users. This report includes:
     - User identification details (Resource ID, display name, principal name)
     - MFA registration status and methods
     - Direct Azure portal links for each user
     - Compliance classification (COMPLIANT/NON_COMPLIANT)
     - Detailed validation status with actionable notes
     - Evaluation timestamp for audit purposes
     - Empty action fields for tracking remediation efforts
   
   The data is fully standardized according to the JQ transformation expression, making it easy to identify non-compliant users requiring MFA enablement and track overall organizational MFA adoption.

## Compliance Truth Table

| MFA Registered (.isMfaRegistered) | ValidationStatusCode | ComplianceStatus | ComplianceStatusReason |
|-----------------------------------|---------------------|------------------|------------------------|
| true | MFA_ENBL | **COMPLIANT** | MFA properly configured and enforced |
| false | MFA_DSBL | **NON_COMPLIANT** | MFA must be enabled to meet security policy requirements |

## Sample Output Structure
```json
{
  "System": "azure",
  "Source": "compliancecow",
  "ResourceID": "12345678-1234-1234-1234-123456789abc",
  "ResourceName": "John Doe",
  "ResourceType": "User",
  "ResourceLocation": "N/A",
  "ResourceTags": [],
  "ResourceURL": "https://portal.azure.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/12345678-1234-1234-1234-123456789abc",
  "UserPrincipalName": "john.doe@company.com",
  "AccountEnabled": true,
  "MFAMethods": ["microsoftAuthenticatorPush", "sms"],
  "MFAEnabled": true,
  "ValidationStatusCode": "MFA_ENBL",
  "ValidationStatusNotes": "Active MFA protection with 2 method(s): microsoftAuthenticatorPush, sms",
  "ComplianceStatus": "COMPLIANT",
  "ComplianceStatusReason": "Compliant - MFA properly configured and enforced",
  "EvaluatedTime": "2025-11-11T10:30:45Z",
  "UserAction": "",
  "ActionStatus": "",
  "ActionResponseURL": ""
}
```