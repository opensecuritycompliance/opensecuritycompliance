# README for SnipeITHardwareInventoryRule

## Purpose of Rule

The purpose of this rule is to **fetch and standardize hardware inventory data** from the **SnipeIT inventory management system**. It retrieves asset information through the SnipeIT API, processes the response, and transforms it into the **ComplianceCow standard format** for compliance monitoring and reporting.

This rule ensures consistent tracking of hardware assets, including their ownership, location, model, warranty, and assignment details.

---

## Inputs with Explanation

The rule requires the following inputs:

1. **ListHardwaresRequestConfig (HTTP_CONFIG)**

   * **Description**: Configuration file containing the HTTP request details for connecting to the SnipeIT API. This file defines the endpoint, headers (such as authentication tokens), request method, and any necessary parameters to fetch the hardware inventory data. Please 
   * **Format**: TOML
   - **Required**: Yes

2. **ProceedIfLogExists (BOOLEAN)**

   * **Description**: A flag that determines whether the rule should continue execution if a log file already exists from a previous run.
   * **Default Value**: `false`
   * **Usage**: Set to `true` to allow reprocessing even if logs are present.
   - **Required**: No

3. **ProceedIfErrorExists (BOOLEAN)**

   * **Description**: A flag that determines whether the rule should continue execution if an error file from a previous run exists.
   * **Default Value**: `false`
   * **Usage**: Useful for retrying executions after handling known issues.
   - **Required**: No

4. **JQExpressionToTransformHardwares (JQ EXPRESSION)**

   * **Description**: A JQ expression used to transform the raw hardware data returned from the SnipeIT API into the **ComplianceCow standard format**.
   * **Transformation Logic**:

     * Extracts fields such as ID, name, category, model, location, serial number, and warranty.
     * Standardizes timestamps and ensures required metadata fields are populated.
   * **Example (Simplified)**:

     ```jq
     .[].rows | map({
       System: "snipeit",
       Source: "compliancecow",
       ResourceID: (.id | tostring),
       ResourceName: .name,
       ResourceType: .category.name,
       ResourceLocation: (.location.name // "Unknown"),
       SerialNumber: .serial,
       ModelName: .model.name,
       Manufacturer: .manufacturer.name,
       AssignedTo: (.assigned_to.name // "Unassigned"),
       EvaluatedTime: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
     })
     ```
     - **Required**: Yes

5. **OutputFileFormat (STRING)**

   * **Description**: Defines the output format for the transformed data file. The rule supports multiple formats for flexibility and downstream integration.
   * **Default Value**: `JSON`
   * **Allowed Values**: `JSON`, `CSV`, `PARQUET`, `YAML`, `TOML`, `XLSX`, `HAR`
   - **Required**: Yes

---

## Outputs with Explanation

The rule produces the following outputs after successful execution:

1. **SnipeITHardwares (FILE)**

   * **Description**: The transformed hardware inventory data file containing all standardized asset details from the SnipeIT system.
   * **Format**: Based on the value of `OutputFileFormat` (e.g., JSON or CSV).
   * **Example Fields**:

     * `ResourceID`
     * `ResourceName`
     * `ResourceType`
     * `Owner`
     * `Location`
     * `SerialNumber`
     * `ModelName`
     * `Manufacturer`
     * `Status`
     * `AssignedTo`
     * `WarrantyExpires`
     * `EvaluatedTime`

2. **LogFile (STRING)**

   * **Description**: A JSON file capturing execution details, including any errors or warnings encountered during API requests, data transformation, or format conversion.
   * **Purpose**: Facilitates debugging and traceability for compliance audits.

3. **ComplianceStatus_ (STRING)**

   * **Description**: Indicates the compliance processing status for the fetched and transformed hardware data.

4. **CompliancePCT_ (INT)**

   * **Description**: A numerical value representing the compliance percentage achieved based on the hardware data’s completeness and validation.

---