**Purpose**: The purpose of this task is to extract and format data from the InputFile using the provided JQ expressions. The task processes a JSON file as input, applies the JQ queries to extract specific columns and rows, and transforms the data into a structured, tabular format. The output file is ready for further analysis or downstream processing, with missing values filled using a default value ('N/A').

### **InputsAndOutputsStructure**:
- Inputs :
    - InputFile                : [MANDATORY] The file containing the response data in which the JQ expression must be executed to extract the relevant columns and rows, supported file formats (JSON only).
    - ColumnSelectorExpression : [MANDATORY] The JQ expression that identifies the columns within the response data.
    - OutputFileName           : [OPTIONAL]  The name of the output file to be generated.
    - RowDataExpression        : [MANDATORY] The JQ expression that identifies the rows or values corresponding to the extracted columns.
    - LogFile                  : [OPTIONAL]  Map the LogFile from the previous task, to handle errors, supported file formats (JSON only).

- Outputs :
    - OutputFile               : The file containing the formatted records, with extracted columns and rows from the response data in a structured format.
    - LogFile                  : A file that contains information about any errors that occurred during the execution of JQ expressions or the data processing.

### **InputsSection**:
1. InputFile **(MANDATORY)**
    - This is a JSON file containing an array of data to be processed using the provided JQ filter/expression. 
    - The file must include the necessary fields for extracting column definitions and row data, as specified in the task configuration.

    **Sample InputFile:**
    ```json
    {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [
                    {
                        "name": "Column1",
                        "type": "string"
                    },
                    {
                        "name": "Column2",
                        "type": "long"
                    },
                    {
                        "name": "Column3",
                        "type": "array"
                    }
                ],
                "rows": [
                    [
                        "Value1",
                        10,
                        "[\"Value1\"]"
                    ],
                    [
                        "Value2",
                        20,
                        "[\"Value2\"]"
                    ]
                ]
            }
        ]
    }
    ```

2. ColumnSelectorExpression **(MANDATORY)**
    - This is a STRING input that contains the JQ filter/expression used to extract column definitions from the InputFile. 
    - The expression identifies the list of columns, their names, and associated metadata required for processing.
    - The output of this JQ expression MUST be an array of JSON objects representing the column definitions.

    **Sample Expression**
    - **Expression** - `.tables[].columns`
    - This extracts the `columns` field from each table in the InputFile.

    **Example Output from Sample InputFile:**
    ```json
    [
        {
            "name": "Column1",
            "type": "string"
        },
        {
            "name": "Column2",
            "type": "long"
        },
        {
            "name": "Column3",
            "type": "array"
        }
    ]
    ```

    **Reference:**
    - [JQ documentation](https://jqlang.github.io/jq/manual/#basic-filters)

3. RowDataExpression **(MANDATORY)**
    - This is a STRING input that contains the JQ filter/expression used to extract row data from the InputFile.  
    - The expression identifies the rows corresponding to the columns selected using the `ColumnSelectorExpression`.  
    - The output of this JQ expression MUST be a 2D array (an array of arrays), where each sub-array represents a single row of data corresponding to the extracted columns.

    **Sample Expression**  
    - **Expression:** `.tables[].rows`  
    - This extracts the `rows` field from each table in the InputFile.

    **Example Output from Sample InputFile:**  
    ```json
    [
        [
            "Value1",
            10,
            "[\"Value1\"]"
        ],
        [
            "Value2",
            20,
            "[\"Value2\"]"
        ]
    ]
    ```

    **Reference:**
    - [JQ Documentation](https://jqlang.github.io/jq/manual/#basic-filters)

4. LogFile **(Optional)**
    - This field is required only when this task is not the first one in the rule.
    - LogFile from the previous task must be mapped to this to handle errors.
    - If mapped correctly, when the previous task returns a 'LogFile', it will pass it to this task and this task won't be executed.Otherwise if there is no 'LogFile from the previous task, this task will execute as expected.

5. OutputFileName **(Optional)**
    - This field is required only when a suitable output file name is needed for the task.
    - If this field value is not provided, the default output file name will be 'OutputFile'.

### **OutputsSection:**
1. OutputFile
    - Each object in the array represents a row of data, with keys corresponding to column names extracted using the ColumnSelectorExpression. 
    - The extracted rows are mapped to their respective columns as specified in the RowDataExpression. 
    - The output preserves nested fields like arrays or JSON objects in their structured format, ensuring compatibility with downstream processes.
    **Sample OutputFile Structure:**  
   ```json
   [
       {
           "Column1": "Value1",
           "Column2": 10,
           "Column3": [
               "Value1"
           ]
       },
       {
           "Column1": "Value2",
           "Column2": 20,
           "Column3": [
               "Value2"
           ]
       }
   ]
   ```  
    **Explanation of the Output Structure:**  
   - Each object in the array represents a row of data, with keys corresponding to column names extracted using the `ColumnSelectorExpression`.  
   - Values are mapped to the appropriate column name for each row, as extracted using the `RowDataExpression`.  
   - Nested fields, such as arrays or JSON objects, are preserved in their structured format.

2. LogFile
    - This file contains information about errors that may have occurred while processing the conditions.