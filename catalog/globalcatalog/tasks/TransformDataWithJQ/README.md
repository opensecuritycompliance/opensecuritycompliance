# TransformDataWithJQ

Transform and modify data records using JQ expressions. Add new columns, rename fields, perform calculations, and restructure data using JQ's powerful transformation capabilities.

## Inputs

- **InputFile**: JSON/CSV/Parquet file with records to transform
- **JQTransform**: JQ expression for data transformation
- **OutputMethod**: (AllowedValues: ALL, FIRST) Specifies whether to return all results from the JQ expression or only the first result.
- **LogConfigFile**: This file defines all exception messages and error-handling details for the current task. It is a TOML file containing predefined fields with placeholder values, which will be dynamically replaced at runtime based on the task’s context. (optional)
- **LogFile**: Map the LogFile from the previous task, to handle errors. (optional)
- **ProceedIfLogExists**: If the previous task returns a log file and passes it to the current task, this field determines whether the current task should proceed and return the log file at the end of execution, or stop immediately and return the log file. The default value is true. (optional, default: true)
- **ProceedIfErrorExists**: If the current task returns an error or if a log file from a previous task is available, this field determines whether to return the log file and continue to the next task, or to stop the entire rule execution. The default value is true. (optional, default: true)

## Output

- **TransformedFile**: JSON file with transformed data
- **LogFile**: File that contains information about errors that have occurred while executing the task.

## Key Transformation Types

### Add Columns
- Fixed values: `map(. + {System: "aws"})`
- From existing fields: `map(. + {ResourceName: .UserName})`
- Calculations: `map(. + {TotalCount: (.items | length)})`
- Current timestamp: `map(. + {ProcessedAt: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))})`

### Conditional Logic
- If-then-else: `map(if .score > 80 then . + {Grade: "Pass"} else . + {Grade: "Fail"} end)`
- Multiple conditions: `map(if .type == "admin" and .active == true then . + {Status: "ACTIVE_ADMIN"} else . + {Status: "OTHER"} end)`

### Field Updates
- Rename fields: `map({NewName: .OldName, Field2: .Field2})`
- String manipulation: `map(.name = (.name | ascii_upcase))`
- Mathematical operations: `map(.score = (.score * 1.1))`

### Array Processing
- Extract from arrays: `map(. + {Reviewers: [.requested_reviewers[].login]})`
- Array calculations: `map(. + {AvgScore: (.scores | add / length)})`

### Field Removal and Reordering
- Remove fields: `map(del(.unwanted_field, .temp_data))`
- Reorder: `map({Name: .Name, ID: .ID, Department: .Department})`

### Data Validation
- Add validation flags: `map(. + {IsValid: (.name != null and .email != null)})`
- Compliance status: `map(. + {Compliant: (.score >= 70 and .reviewed == true)})`

## How It Works

1. Reads input data file (JSON, CSV, or Parquet)
2. Applies the JQ transformation expression to all records
3. Outputs transformed data as Parquet file
4. Uses description for documentation and logging

## Use Cases

- **Data Enrichment**: Add calculated fields, timestamps, and derived values
- **Data Cleaning**: Standardize formats, fix inconsistencies, remove invalid data
- **Compliance Processing**: Add validation status, compliance flags, and audit fields
- **Data Restructuring**: Reorganize fields, flatten nested data, create summary fields
- **Business Logic**: Apply complex rules, categorizations, and transformations

## Best Practices

1. **Test Incrementally**: Start with simple transformations and build complexity
2. **Document Purpose**: Always provide clear JQ descriptions
3. **Handle Nulls**: Use `// default_value` for missing data
4. **Validate Results**: Check output structure matches expectations
5. **Performance**: Keep expressions efficient for large datasets