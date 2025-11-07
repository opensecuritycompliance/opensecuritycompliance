# TransformDataWithJQ

Transform and modify data records using JQ expressions. Add new columns, rename fields, perform calculations, and restructure data using JQ's powerful transformation capabilities.

## Inputs

- **InputFile**: JSON/CSV/Parquet file with records to transform
- **JQTransform**: JQ expression for data transformation
- **JQDescription**: Plain English explanation of the transformation (optional)

## Output

- **TransformedFile**: JSON file with transformed data

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