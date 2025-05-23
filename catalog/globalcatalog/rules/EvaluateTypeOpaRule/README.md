# How to Use the OPA Rule

## Purpose

The purpose of this rule is to evaluate resource compliance and enforce policies using the Open Policy Agent (OPA). By defining criteria for inclusion, exclusion, and specific policies, this rule ensures that specified resources comply with governance requirements. The results of the evaluation can be stored in a report, facilitating further analysis, auditing, and compliance tracking.

## Overview
To use this rule, you need to provide certain inputs. There are two methods available:

**Note:** The `ConfigFile` is mandatory for both methods.

### Method 1: General Rule
For a general application, provide the following inputs (ignore `OpaConfigurationFile`):

- `IncludeCriteria`
- `ExcludeCriteria`
- `RegoFile`
- `Query`
- `OutputFileName`
- `ConfigFile`

### Method 2: Using OPA Template
For a pre-configured approach, provide only the following inputs:

- `OpaConfigurationFile`
- `ConfigFile`

**All other inputs should be ignored when using this method.**

## Input Descriptions

### IncludeCriteria
- **Purpose:** Specifies which resources to include. Use "*" to include everything.
- **Example:** To include specific pods, use `/cluster/*/namespace/*/pod/pod1,pod2,pod3,pod4`.

### ExcludeCriteria
- **Purpose:** Specifies which resources to exclude. Use "*" to exclude everything.
- **Example:** To exclude specific pods, use `/cluster/*/namespace/*/pod/pod1,pod2`.

### RegoFile
- **Purpose:** Upload the `sample.rego` file to MinIO and provide the file path. This file contains the policy rules to be executed.
- **Example:** Path to the sample file: `catalog/globalcatalog/rules/EvaluateTypeOpaRule/oparuletemplatewithstrings.yaml`. Specify the path under the `regostring` section.

### Query
- **Purpose:** Defines the specific query to execute within the rego file.
- **Example:** To only execute the `deny` function, use `data.package_name.deny[x]`.

### OpaConfigurationFile
- **Purpose:** Provide all required inputs in a single configuration file, simplifying the configuration process.
- **Example:** Sample configuration file path: `catalog/globalcatalog/rules/EvaluateTypeOpaRule/oparuletemplatewithstrings.yaml`.

### ConfigFile
- **Purpose:** Contains compliance details and defines the format for outputs. It ensures consistency across evaluations. Create a table with `OutputFileName` in a valid format.
- **Example:** Sample configuration file: "catalog/globalcatalog/rules/EvaluateTypeOpaRule/Config.toml".

### OutputFileName
- **Purpose:**
  1. Specifies the name of the generated output report.
  2. Retrieves compliance details from the `ConfigFile`.
- **Example:** `OpaPolicyReport`

## Output Files

The OPA rule generates several output files as part of the evaluation process. Below is a list of possible outputs:
- **OpaPolicyReport:**
  1. Contains the compliance details and policy evaluation results, such as whether resources are compliant or non-compliant with the defined policies.
- **DataFile:**
  1. Stores the processed manifest data after applying include and exclude criteria. This file provides details on the resources evaluated.
- **LogFile:**
  1. Records logs, including errors, for debugging and auditing purposes.

These files are structured for easy readability and integration with other tools or systems.

### Final Notes
To ensure successful evaluation:
- Verify that all file paths and names are correctly specified.
- Select the appropriate method based on your requirements:
  - **Method 1**: Use for general rule execution.
  - **Method 2**: Use for template-based configurations.

By adhering to these guidelines, you can simplify resource evaluation, ensure efficient policy enforcement, and achieve consistent compliance with ease.