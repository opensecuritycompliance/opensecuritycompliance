# README for AWSBedrockAIAgentPrivilegedAccessAudit

## Purpose of Rule

The **`AWSBedrockAIAgentPrivilegedAccessAudit`** rule audits AWS Bedrock AI agents and custom applications using Bedrock APIs to identify agents with privileged IAM permissions. It tracks invocation history, identifies who or what invokes the agents, evaluates privileged access patterns, and produces a compliance report requiring manual review for privileged AI agents.

Key capabilities of `AWSBedrockAIAgentPrivilegedAccessAudit`:

1. **Bedrock Native Agent Discovery**: Retrieves AWS Bedrock native AI agents and their detailed configuration, including agent ID, name, ARN, foundation model, status, and IAM execution role.

2. **Custom Bedrock API Caller Discovery**: Identifies custom applications or AI agents that interact with AWS Bedrock APIs and consolidates them with native Bedrock agents.

3. **CloudTrail Invocation Tracking**: Retrieves CloudTrail-related information and queries CloudWatch Logs to identify Bedrock agent/API invocation activity, including invoker identity, invocation time, source IP, and MFA information.

4. **Agent and Invocation Consolidation**: Combines native Bedrock agents and custom API callers and joins them with invocation information to determine unique invokers and total invocation activity.

5. **IAM Policy Retrieval**: Retrieves IAM policies attached to the execution roles associated with native Bedrock agents and custom API callers.

6. **Policy Version and Document Analysis**: Retrieves the default IAM policy version and extracts the complete policy document for privileged-access evaluation.

7. **Privileged Access Detection**: Identifies privileged AI agents based on privileged IAM policies and high-risk IAM actions, including administrative permissions, IAM access, deletion capabilities, Bedrock invocation permissions, KMS decryption, and Secrets Manager access.

8. **Compliance Evaluation**: Adds compliance metadata including validation status, compliance status, compliance reason, evaluation timestamp, and manual-review action information.

9. **Compliance Report Generation**: Produces a comprehensive `PrivilegedAIAgentsComplianceReport` containing agent details, IAM policy information, invocation tracking, and compliance findings.

---

## When and Where to Use

Use `AWSBedrockAIAgentPrivilegedAccessAudit` in the following scenarios:

* **Privileged AI Agent Auditing**: When AWS Bedrock AI agents need to be evaluated for excessive or privileged IAM permissions.

* **Custom AI Application Auditing**: When applications or custom AI agents use AWS Bedrock APIs and their associated IAM execution roles need to be assessed.

* **AI Agent Invocation Accountability**: When identifying who invokes AI agents and determining whether invocation originates from human IAM users, assumed roles, or service accounts.

* **Autonomous AI Risk Assessment**: When privileged AI agents need additional review because they may perform privileged operations autonomously.

* **Continuous Compliance Monitoring**: When privileged AI-agent access needs to be tracked together with invocation history and IAM policy information.

---

## Inputs with Explanation

The rule requires the following configuration inputs:

1. **`fetch_bedrock_agents_RequestConfigFile` (HTTP_CONFIG)**:

   - **Description**: HTTP request configuration used to retrieve AWS Bedrock native AI agent information.
   - **Data Type**: `HTTP_CONFIG`
   - **Required**: Yes
   - **Format**: TOML

2. **`fetch_bedrock_api_callers_RequestConfigFile` (HTTP_CONFIG)**:

   - **Description**: HTTP request configuration used to retrieve custom applications or API callers interacting with AWS Bedrock.
   - **Data Type**: `HTTP_CONFIG`
   - **Required**: Yes
   - **Format**: TOML

3. **`fetch_ai_agent_policies_RequestConfigFile` (HTTP_CONFIG)**:

   - **Description**: HTTP request configuration used to retrieve IAM policies attached to native Bedrock agent execution roles.
   - **Data Type**: `HTTP_CONFIG`
   - **Required**: Yes
   - **Format**: TOML

4. **`FetchAPICallersResponseConfigFile` (HTTP_CONFIG)**:

   - **Description**: Response configuration used while processing Bedrock API caller information.
   - **Data Type**: `HTTP_CONFIG`
   - **Required**: Yes
   - **Format**: TOML

5. **`FormatDateTimeJQConfigFile` (FILE)**:

   - **Description**: JQ configuration used to format the start and end date/time values required for invocation analysis.
   - **Data Type**: `FILE`
   - **Required**: Yes
   - **Format**: TOML

6. **`GetCloudTrialDetailsRequestConfig` (HTTP_CONFIG)**:

   - **Description**: HTTP request configuration used to retrieve CloudTrail-related information.
   - **Data Type**: `HTTP_CONFIG`
   - **Required**: Yes
   - **Format**: TOML

7. **`GetAWSAccountIdRequestConfig` (HTTP_CONFIG)**:

   - **Description**: HTTP request configuration for retrieving AWS account information used by the workflow.
   - **Data Type**: `HTTP_CONFIG`
   - **Required**: Yes
   - **Format**: TOML

8. **`FilterS3BucketDetailsJQConfigFile` (FILE)**:

   - **Description**: JQ configuration used to filter S3 bucket details obtained from the CloudTrail-related workflow.
   - **Data Type**: `FILE`
   - **Required**: Yes
   - **Format**: TOML

9. **`MergeType` (STRING)**:

   - **Description**: Determines how CloudTrail-related data and time details are merged.
   - **Data Type**: `STRING`
   - **Required**: Yes
   - **Allowed Values**:
     - `APPEND`
     - `CONCATENATE`
   - **Default**: `CONCATENATE`

10. **`OutputFileFormat` (STRING)**:

    - **Description**: Determines the output file format used by the data-processing tasks.
    - **Data Type**: `STRING`
    - **Required**: Yes
    - **Allowed Values**:
      - `JSON`
      - `CSV`
      - `PARQUET`
    - **Default**: `JSON`

11. **`QueryCloudWatchLogsRequestConfig` (HTTP_CONFIG)**:

    - **Description**: HTTP request configuration used to query CloudWatch Logs for Bedrock invocation events.
    - **Data Type**: `HTTP_CONFIG`
    - **Required**: Yes
    - **Format**: TOML

12. **`GetQueryResultRequestConfig` (HTTP_CONFIG)**:

    - **Description**: HTTP request configuration used to retrieve the results of the CloudWatch Logs query.
    - **Data Type**: `HTTP_CONFIG`
    - **Required**: Yes
    - **Format**: TOML

13. **`FormatQueryResponseJQConfigFile` (FILE)**:

    - **Description**: JQ configuration used to transform CloudWatch query results into structured invocation records.
    - **Data Type**: `FILE`
    - **Required**: Yes
    - **Format**: TOML

14. **`ConsolidateAIAgentsSQLConfig` (FILE)**:

    - **Description**: SQL configuration used to consolidate native Bedrock agents and custom Bedrock API callers.
    - **Data Type**: `FILE`
    - **Required**: Yes
    - **Format**: TOML

15. **`GetBedrockAgentsDetailsRequestConfigFile` (HTTP_CONFIG)**:

    - **Description**: HTTP request configuration used to retrieve detailed information for discovered Bedrock agents.
    - **Data Type**: `HTTP_CONFIG`
    - **Required**: Yes
    - **Format**: TOML

16. **`FlattenAIAgentsJQExpression` (JQ_EXPRESSION)**:

    - **Description**: JQ expression used to extract individual agent objects from the Bedrock API response.
    - **Data Type**: `JQ_EXPRESSION`
    - **Required**: Yes
    - **Default**:
      ```jq
      .[].agent
      ```

17. **`OutputMethod` (STRING)**:

    - **Description**: Determines whether the JQ processing returns the first result or all results.
    - **Data Type**: `STRING`
    - **Required**: Yes
    - **Allowed Values**:
      - `FIRST`
      - `ALL`
    - **Default**: `ALL`

18. **`JoinAgentsWithInvocationsSQLConfig` (FILE)**:

    - **Description**: SQL configuration used to join consolidated agent information with CloudWatch/CloudTrail invocation information.
    - **Data Type**: `FILE`
    - **Required**: Yes
    - **Format**: TOML

19. **`FilterBedrockNativeAgentsJQConfigFile` (FILE)**:

    - **Description**: JQ configuration used to select native Bedrock agents before retrieving their IAM policies.
    - **Data Type**: `FILE`
    - **Required**: Yes
    - **Format**: TOML

20. **`FilterCustomAPICallersJQConfigFile` (FILE)**:

    - **Description**: JQ configuration used to select custom Bedrock API callers before retrieving their IAM policies.
    - **Data Type**: `FILE`
    - **Required**: Yes
    - **Format**: TOML

21. **`FetchCustomCallerPoliciesRequestConfigFile` (HTTP_CONFIG)**:

    - **Description**: HTTP request configuration used to retrieve IAM policies associated with custom Bedrock API callers.
    - **Data Type**: `HTTP_CONFIG`
    - **Required**: Yes
    - **Format**: TOML

22. **`IncludeInputFieldsResponseConfigFile` (HTTP_CONFIG)**:

    - **Description**: Response configuration used to retain input fields while processing IAM policy API responses.
    - **Data Type**: `HTTP_CONFIG`
    - **Required**: Yes
    - **Format**: TOML

23. **`FlattenPoliciesJQConfigFile` (FILE)**:

    - **Description**: JQ configuration used to flatten IAM policy attachment responses into structured policy records.
    - **Data Type**: `FILE`
    - **Required**: Yes
    - **Format**: TOML

24. **`PoliciesMergeType` (STRING)**:

    - **Description**: Determines how native-agent and custom-caller policy records are merged.
    - **Data Type**: `STRING`
    - **Required**: Yes
    - **Allowed Values**:
      - `APPEND`
      - `CONCATENATE`
    - **Default**: `APPEND`

25. **`FetchPolicyDetailsRequestConfig` (HTTP_CONFIG)**:

    - **Description**: HTTP request configuration used to retrieve detailed IAM policy metadata.
    - **Data Type**: `HTTP_CONFIG`
    - **Required**: Yes
    - **Format**: TOML

26. **`FlattenPolicyDetailsJQConfigFile` (FILE)**:

    - **Description**: JQ configuration used to flatten IAM policy metadata.
    - **Data Type**: `FILE`
    - **Required**: Yes
    - **Format**: TOML

27. **`FetchPolicyVersionDetailsRequestConfig` (HTTP_CONFIG)**:

    - **Description**: HTTP request configuration used to retrieve the default IAM policy version.
    - **Data Type**: `HTTP_CONFIG`
    - **Required**: Yes
    - **Format**: TOML

28. **`FlattenPolicyDocumentDetailsJQConfig` (FILE)**:

    - **Description**: JQ configuration used to decode and extract the IAM policy document from the policy version response.
    - **Data Type**: `FILE`
    - **Required**: Yes
    - **Format**: TOML

29. **`FilterPrivilegedPolicyDetailsJQConfigFile` (FILE)**:

    - **Description**: JQ configuration used to identify policy records containing privileged policies or privileged/high-risk actions.
    - **Data Type**: `FILE`
    - **Required**: Yes
    - **Format**: TOML

30. **`JoinPolicyDataWithInvocationsSQLConfigFile` (FILE)**:

    - **Description**: SQL configuration used to combine privileged policy information with previously collected agent and invocation information.
    - **Data Type**: `FILE`
    - **Required**: Yes
    - **Format**: TOML

31. **`ComplianceLogicJQConfigFile` (FILE)**:

    - **Description**: JQ configuration used to generate compliance metadata and the final privileged AI-agent compliance report.
    - **Data Type**: `FILE`
    - **Required**: Yes
    - **Format**: TOML

## Output File

The rule generates the `PrivilegedAIAgentsComplianceReport` output file using the `add_compliance_logic` JQ configuration.

The output contains one compliance record for each evaluated AI agent. The record combines:

- AI agent identification and resource information
- IAM role information
- Evaluated IAM policy information
- Invocation and invoker information
- Privileged-access evaluation
- Compliance status and review information

### Output Structure

```json
{
  "System": "aws",
  "Source": "bedrock",
  "ResourceID": "<Agent ARN>",
  "ResourceName": "<Agent Name>",
  "ResourceType": "BedrockAIAgent",
  "ResourceLocation": "us-west-2",
  "ResourceTags": {},

  "AgentID": "<Agent ID>",
  "AgentName": "<Agent Name>",
  "AgentARN": "<Agent ARN>",
  "AgentType": "<Agent Type>",

  "IAMRoleARN": "<IAM Role ARN>",
  "IAMRoleName": "<IAM Role Name>",

  "PolicyId": "<Policy ID>",
  "PolicyName": "<Policy Name>",
  "PolicyArn": "<Policy ARN>",
  "PolicyPath": "<Policy Path>",
  "DefaultVersionId": "<Default Policy Version>",
  "AttachmentCount": "<Attachment Count>",
  "IsAttachable": "<true/false>",
  "CreateDate": "<Policy Creation Date>",
  "UpdateDate": "<Policy Update Date>",
  "PolicyDocument": {
    "...": "Evaluated IAM policy document"
  },

  "UniqueInvokers": "<Number of Unique Invokers>",
  "TotalInvocations": "<Total Invocation Count>",
  "FirstInvocationDate": "<First Invocation Date>",
  "LastInvocationDate": "<Last Invocation Date>",
  "InvokerDetails": [
    {
      "InvokerArn": "<Invoker ARN>",
      "InvokerType": "<Invoker Type>",
      "InvokerPrincipalId": "<Principal ID>",
      "SourceIP": "<Source IP>",
      "MFAAuthenticated": "<true/false>",
      "EventTime": "<Invocation Time>"
    }
  ],

  "ValidationStatusCode": "<PRIV_AI_AGNT_ACCS>",
  "ValidationStatusNotes": "<Validation summary>",
  "ComplianceStatus": "<COMPLIANT or NON_COMPLIANT>",
  "ComplianceStatusReason": "<Compliance evaluation reason>",

  "EvaluatedTime": "<Evaluation Timestamp>",
  "UserAction": "",
  "ActionStatus": "",
  "ActionResponseURL": ""
}
```

## Authors
- Shradha Krish
- Ram Manavalan
- Megha Shah
- Arul G
- Raj Krishnamurthy
- Rohith
- Mosi Platt