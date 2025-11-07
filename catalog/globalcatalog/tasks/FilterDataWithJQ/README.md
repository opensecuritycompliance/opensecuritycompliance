# FilterDataWithJQ

Transform and modify data records using JQ expressions. Add new columns, rename fields, and perform complex data transformations.

## Inputs

- **InputFile**: JSON/CSV/Parquet file with records to transform
- **JQFilter**: JQ expression for data transformation
- **JQDescription**: Plain English explanation of what the JQ transformation does (optional)

## Output

- **FilteredFile**: JSON file with transformed data

## JQ Filter Examples

### Add New Column
```bash
map(. + {priority: (if .cvssScore > 7.0 then "high" else "low" end)})
```
**Description**: "Add a priority column that marks vulnerabilities as 'high' if CVSS score is above 7.0, otherwise 'low'"

### Rename Columns
```bash
map({vuln_id: .id, description: .title, score: .cvssScore})
```
**Description**: "Rename columns: id becomes vuln_id, title becomes description, and keep cvssScore as score"

### Multiple Transformations
```bash
map(. + {
  risk_level: (
    if .cvssScore > 8.5 then "critical"
    elif .cvssScore > 6.0 then "high"
    else "medium"
    end
  ),
  patch_status: (if .isPatchable then "available" else "none" end)
} | {
  id: .vuln_id,
  title: .description,
  risk: .risk_level,
  patching: .patch_status
})
```
**Description**: "Add risk level categorization based on CVSS score, add patch status, then restructure the output with only specific fields"

### Filter and Transform
```bash
map(select(.cvssScore > 5.0) | . + {filtered: true})
```
**Description**: "Keep only records with CVSS score above 5.0 and add a 'filtered' flag to each record"

## How It Works

1. Takes the JQ transformation expression and optional plain English description
2. Validates the JQ expression syntax using sample data
3. If validation passes, applies transformation to InputFile
4. Outputs single transformed file
5. Uses the description for documentation and logging purposes

## JQ Description Field

The **JQDescription** field is optional but highly recommended for:
- **Documentation**: Helps team members understand what the transformation does
- **Maintenance**: Makes it easier to modify or debug transformations later
- **Compliance**: Provides audit trail of data processing logic
- **Training**: Helps new users learn JQ syntax by seeing examples with explanations

## Use Cases

- Add calculated columns based on existing data
- Rename fields for standardization  
- Apply business logic transformations
- Combine multiple data manipulations in one step
- Clean and restructure data format
- Document complex transformations with plain English descriptions

## Best Practices

1. Always provide a clear **JQDescription** explaining the transformation logic
2. Test your JQ expressions with sample data before running on large datasets
3. Use meaningful descriptions that explain both what and why
4. Break down complex transformations into simpler steps when possible