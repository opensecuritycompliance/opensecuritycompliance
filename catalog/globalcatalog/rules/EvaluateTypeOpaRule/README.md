# How to Use the OPA Rule

## Overview
To use this rule, you need to provide certain inputs. There are two methods available:

**Note:** The `ConfigFile` is required for both methods.

### Method 1: General Rule
Provide the following inputs (ignore `OpaConfigurationFile`):

- `IncludeCriteria`
- `ExcludeCriteria`
- `RegoFile`
- `Query`
- `OutputFileName`
- `ConfigFile`

### Method 2: Using OPA Template
Provide `OpaConfigurationFile` and `ConfigFile`, and ignore the other inputs.

## Input Descriptions

### IncludeCriteria
- **What it does:** Specify which resources to include. Use "*" to include everything.
- **Example:** To include specific pods, use `/cluster/*/namespace/*/pod/pod1,pod2,pod3,pod4`.

### ExcludeCriteria
- **What it does:** Specify which resources to exclude. Use "*" to exclude everything.
- **Example:** To exclude specific pods, use `/cluster/*/namespace/*/pod/pod1,pod2`.

### RegoFile
- **What it does:** Upload the `sample.rego` file to MinIO and provide the file path.
- **Example:** Path to the sample file: "catalog/globalcatalog/rules/EvaluateTypeOpaRule/oparuletemplatewithstrings.yaml" in the `regostring` section.

### Query
- **What it does:** Specify the query to execute the rego file.
- **Example:** To only execute the `deny` function, use `data.package_name.deny[x]`.

### OpaConfigurationFile
- **What it does:** Provide all necessary inputs in a single file, ignoring other rule inputs.
- **Example:** Sample configuration file location: "catalog/globalcatalog/rules/EvaluateTypeOpaRule/oparuletemplatewithstrings.yaml".

### ConfigFile
- **What it does:** Maintains all compliance details. Create a table with `OutputFileName` in a valid format.
- **Example:** Sample configuration file: "catalog/globalcatalog/rules/EvaluateTypeOpaRule/Config.toml".

### OutputFileName
- **What it does:** 
  1. Names the output report.
  2. Retrieves compliance details from the config file.
- **Example:** `OpaPolicyReport`