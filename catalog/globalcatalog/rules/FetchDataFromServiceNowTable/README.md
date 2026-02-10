# README for FetchDataFromServiceNowTable

## Purpose of Rule

The purpose of this rule is to fetch data from a specified ServiceNow table based on provided table name and query parameters. It executes an HTTP request to retrieve records from ServiceNow and processes the response according to the configured settings.

## Inputs with Explanation

The rule requires the following inputs:

1. **ServiceNowTableRequestConfig (HTTP_CONFIG)**:
   - **Description**: Configuration file in TOML format that defines the HTTP request parameters for connecting to ServiceNow. This includes endpoint URL, authentication details, HTTP method, headers, and query parameters.
   - **Format**: TOML
   - **Required**: Yes

2. **ServiceNowTableResponseConfig (HTTP_CONFIG)**:
   - **Description**: Configuration file in TOML format that defines how to process and parse the HTTP response from ServiceNow. This includes response mapping, data extraction rules, and error handling settings.
   - **Format**: TOML
   - **Required**: Yes

3. **ServiceNowTableConfig (FILE)**:
   - **Description**: JSON configuration file that specifies the ServiceNow table name and query parameters for fetching data. This file defines which table to query and what filters to apply.
   - **Format**: JSON
   - **Required**: Yes
   - **Example**: `{"table": "incident", "query": "active=true^priority=1"}`

4. **ProceedIfLogExists (BOOLEAN)**:
   - **Description**: A flag that determines whether the rule should proceed with execution if a log file is passed from a previous rule. Set to `true` to continue execution even if logs are present, or `false` to halt execution when logs exist.
   - **Default**: false
   - **Required**: No

5. **ProceedIfErrorExists (BOOLEAN)**:
   - **Description**: A flag that determines whether the rule should continue execution if an error occurs at the current rule level. Set to `true` to proceed despite errors, or `false` to stop the rule execution when errors are encountered.
   - **Default**: false
   - **Required**: No

6. **ServiceNowInputFileValidationConfig (FILE)**:
   - **Description**: JSON configuration file that validates the `ServiceNowTableConfig` input file. This ensures that the ServiceNow table configuration contains all required fields.
   - **Format**: JSON
   - **Required**: Yes
   - **Example**: `{"TableName": "sn_si_incident"}`

## Outputs with Explanation

The rule generates the following outputs after processing:

1. **CompliancePCT_ (INT)**:
   - **Description**: A calculated compliance percentage value indicating the success rate or compliance level of the data fetching operation. This metric helps assess the quality and completeness of the retrieved data.

2. **ComplianceStatus_ (STRING)**:
   - **Description**: A status indicator showing whether the data retrieval operation met compliance requirements. Possible values include "COMPIANT", "NON_COMPLIANT".

3. **LogFile (FILE)**:
   - **Description**: If any errors occur during execution (e.g., connection failures, authentication issues, invalid responses, validation errors), an error log is generated in JSON format. This file contains detailed error messages.

4. **ServiceNowRecords (FILE)**:
   - **Description**: A JSON file containing the records retrieved from the specified ServiceNow table. This is the primary output file with all fetched data structured according to the response configuration. The data includes all fields requested from the ServiceNow table based on the query parameters provided.