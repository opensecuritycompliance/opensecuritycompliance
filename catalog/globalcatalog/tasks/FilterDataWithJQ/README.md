# FilterDataWithJQ

Transform and modify data records using JQ expressions. Add new columns, rename fields, and perform complex data transformations.

## Inputs

- **InputFile**: JSON/CSV/Parquet file with records to transform
- **JQFilter**: JQ expression for data transformation
- **OutputMethod**: (AllowedValues: ALL, FIRST) Specifies whether to return all results from the JQ expression or only the first result.
- **LogConfigFile**: This file defines all exception messages and error-handling details for the current task. It is a TOML file containing predefined fields with placeholder values, which will be dynamically replaced at runtime based on the task’s context. We can also include the from and to dates in the error message for better clarity using the {fromdate} and {todate} placeholders. (optional)
- **LogFile**: Map the LogFile from the previous task, to handle errors. (optional)
- **ProceedIfLogExists**: If the previous task returns a log file and passes it to the current task, this field determines whether the current task should proceed and return the log file at the end of execution, or stop immediately and return the log file. The default value is true. (optional, default: true)
- **ProceedIfErrorExists**: If the current task returns an error or if a log file from a previous task is available, this field determines whether to return the log file and continue to the next task, or to stop the entire rule execution. The default value is true. (optional, default: true)

## Output

- **FilteredFile**: JSON file with transformed data
- **LogFile**: File that contains information about errors that have occurred while executing the task.

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

## Output Method Examples
- **Inputs**
    - InputFile
    ```json
    [
        {
            "repositories": [
                {"Name": "repo1"},
                {"Name": "repo4"}
            ],
            "nextPageToken": "token1"
        },
        {
            "repositories": [
                {"Name": "repo2"}
            ],
            "nextPageToken": "token2"
        },
        {
            "repositories": [
                {"Name": "repo3"},
                {"Name": "repo5"}
            ]
        }
    ]
    ```

    - JQFilter: `.[].repositories[]`
    
- **OutputMethod - FIRST:**
    - Considers only the first result of the JQ expression
        - Output
        ```json
        [
            {
                "Name": "repo1"
            }
        ]
        ```

- **OutputMethod - ALL:**
    - Considers all the results of the JQ expression
        
        - Output
        ```json
        [
            {
                "Name": "repo1"
            },
            {
                "Name": "repo4"
            },
            {
                "Name": "repo2"
            },
            {
                "Name": "repo3"
            },
            {
                "Name": "repo5"
            }
        ]
        ```

## How It Works

1. Takes the JQ transformation expression and optional plain English description
2. Validates the JQ expression syntax using sample data
3. If validation passes, applies transformation to InputFile
4. Outputs single transformed file
5. Uses the description for documentation and logging purposes

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