The purpose of this task is to extract data from the InputFile based on the provided JQ filter/expression. The task expects a JSON file and JQ filter/expression as inputs, and provides the extracted data as JSON file in the output.

### **InputsAndOutputsStructure:**

- Inputs :
    - **InputFile** : [MANDATORY] The file that contains the records in which the JQ expression must be executed.
    - **JQConfigFile** : [MANDATORY] The TOML file that contains the JQExpression & OutputMethod.
    - **JQExpression** : [OPTIONAL] A string of the JQExpression
    - **OutputMethod** : [OPTIONAL] Output method for the JQExpression
    - **LogConfigFile** : [OPTIONAL] This file defines all exception messages and error-handling details for the current task. It is a TOML file containing predefined fields with placeholder values, which will be dynamically replaced at runtime based on the task’s context.
    - **LogFile** : [OPTIONAL] Map the LogFile from the previous task, to handle errors.
    - **ChunksPerIteration**: [OPTIONAL] It defines how many data items are processed at once to improve performance and manage large datasets efficiently.
    - **ProceedIfLogExists** : [OPTIONAL] If the previous task returns a log file and passes it to the current task, this field determines whether the current task should proceed and return the log file at the end of execution, or stop immediately and return the log file. The default value is true.
    - **ProceedIfErrorExists** : [OPTIONAL] If the current task returns an error or if a log file from a previous task is available, this field determines whether to return the log file and continue to the next task, or to stop the entire rule execution. The default value is true.
    
- Outputs :
    - **OutputFile** : File that contains the output of the JQ expression.
    - **LogFile** : File that contains information about errors that have occurred while executing the task.

### **InputsSection:**

1. InputFile **(MANDATORY)**
    - This is a file containing an array of data with which the JQ filter/expression must be executed.
    
    **Sample InputFile:**
    
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
    
2. JQConfigFile: **(MANDATORY)**
    - `JQConfigFile` file contains the JQExpression & OutputMethod in the TOML structure.
    - Below is the structure of the JQConfig file.
    
    **JQConfigFile Structure:**
    
    ```toml
    [JQConfig]
    JQExpression = ".[].repositories[]" # [MANDATORY] Contains the JQ filter/expression that must be executed on the InputFile data
    OutputMethod = "ALL" # [OPTIONAL] (AllowedValues: FIRST, ALL) Specifies whether to consider all outputs from the JQ expression, or only the first one
    ```
    
    #### **JQExpression**
    - This is a STRING input that contains the JQ filter/expression that must be executed on the InputFile data
    - The output provided by the JQ filter/expression MUST be either a JSON object, or an array of JSON objects
    - Example: `.[].repositories[]`
    - [Refer the documentation](https://jqlang.github.io/jq/manual/#basic-filters) for more info
    
    #### **OutputMethod**
    - This is a STRING input that specifies whether to consider all outputs from the JQ expression, or only the first one (default)
    - This input accepts the following values: `'FIRST' & 'ALL'`
    - If no input is provided, then the default value 'FIRST' is used
    
    - **OutputMethod - FIRST:**
        - Considers only the first output that is provided by the JQ expression
    
            ```jsonc
            // TASK INPUTS
    
            // InputFile
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
    
            // JQExpression -> '.[].repositories[]'
    
            // OutputMethod -> 'FIRST'
    
    
            // TASK OUTPUT
    
            // OutputFile
            [
                {
                    "Name": "repo1"
                }
            ]
            ```

    - **OutputMethod - ALL:**
        - Considers all the outputs provided by the JQ expression
    
            ```jsonc
            // TASK INPUTS
    
            // InputFile
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
    
            // JQExpression -> '.[].repositories[]'
    
            // OutputMethod -> 'ALL'
    
    
            // TASK OUTPUT
    
            // OutputFile
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

3. JQExpression **(Optional)**
    - Either JQConfig file or JQExpression is sufficient. If both are provided, the JQConfig file will be used by default.
    - This is a STRING input that contains the JQ filter/expression that must be executed on the InputFile data
    - The output provided by the JQ filter/expression MUST be either a JSON object, or an array of JSON objects
    - Example: `.[].repositories[]`
    - [Refer the documentation](https://jqlang.github.io/jq/manual/#basic-filters) for more info

4. OutputMethod **(Optional)**
    - This is a STRING input that specifies whether to consider all outputs from the JQ expression, or only the first one.
    - This input accepts the following values: `'FIRST' & 'ALL'`
    
5. LogConfigFile **(Optional)**
    - This file defines exception messages and error-handling logic for the current task.
    - It is a TOML file containing predefined fields with placeholders that are dynamically replaced at runtime based on the task’s context.
    - If a placeholder in the TOML file cannot be resolved at runtime, an error will be raised.
    
    For example: 
    
    ```toml
    [ExtractDataUsingJQ]
        ##### INPUT_FILE EXCEPTIONS #####
        InputFile.missing = "InputFile is missing in user inputs."
        InputFile.type_error = "InputFile must be a JSON file, got file with '{extension}' extension instead"
        InputFile.download_error = "Error while downloading InputFile :: {error}"
        InputFile.empty = "The input file is empty. Please verify that the file contains valid data before proceeding."
        
        ##### JQ EXCEPTIONS #####
        JQExpression.no_result = "The JQ expression returned no results. Please check the query and ensure the input data matches the expected structure."
        JQExpression.invalid_result = "JQExpression must return an object or an array, got '{jq_result_type}' instead"
        
        ##### OUTPUT_FILE EXCEPTIONS #####
        OutputFile.upload_error = "An error occurred while uploading the result: {error}. Please check the error details and try again"
        
        ##### LOG_FILE EXCEPTIONS #####
        LogFile.download_error = "Error while downloading LogFile :: {error}"
        
        ##### JQ_CONFIG_FILE EXCEPTIONS #####
        JQConfigFile.missing = "'JQConfig' file is missing. Please ensure the configuration file is present. Please refer to the provided JQConfig-sample.toml file."
        JQConfigFile.download_error = "Error occurred while downloading JQConfig file :: {error}"
        JQConfigFile.jq_config_field_missing_or_empty = "'JQConfig' table is missing or empty in the provided JQConfig file. Please refer to the JQConfig-sample.toml file."
    ```
    
    In this example, the `{placeholder}` will be replaced with the actual value at runtime. If the placeholder is invalid or cannot be resolved, the system will raise an error.

    We can also include the from and to dates in the error message for better clarity using the {fromdate} and {todate} placeholders.
    
6. LogFile **(Optional)**
    - This field is required only when this task is not the first one in the rule.
    - LogFile from the previous task must be mapped to this to handle errors.
    - If mapped correctly, when the previous task returns a `LogFile`, it will pass it to this task and this task won’t be executed.Otherwise if there is no ’LogFile from the previous task, this task will execute as expected.
       
7. ChunksPerIteration **(Optional)**
    - `ChunksPerIteration` controls how many records are processed at a time. It helps handle large datasets by breaking them into smaller, manageable parts.
    - This improves performance and reduces the risk of system errors. Adjusting this value can help optimize processing speed and resource usage.
     
8. ProceedIfLogExists **(Optional)**
    - This field is optional, and the default value of `ProceedIfLogExists` is true.
    - If `ProceedIfLogExists` is set to true, the task will continue its execution and return the LogFile at the end.
    - If it is set to false and a log file is already present, the task will skip further execution and simply return the existing LogFile.
    
9. ProceedIfErrorExists **(Optional)**
    - This field is optional, and the default value of `ProceedIfErrorExists` is true.
    - If `ProceedIfErrorExists` is set to true, the task will return the error details as part of the LogFile and continue to the next task.
    - If it is set to false, the error details will be returned, and the entire rule execution will be stopped.


### **OutputsSection:**

1. OutputFile
    - This file contains the output of the JQ expression.
2. LogFile
    - This file contains information about errors that may have occurred while executing the task.