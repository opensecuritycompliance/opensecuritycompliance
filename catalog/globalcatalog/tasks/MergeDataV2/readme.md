The purpose of this task is to merge two files given as input, into one consolidated file. This task has two functionalities:
- APPEND: Merges the rows from both files. This is the default behaviour.
- CONCATENATE: Merges the columns from both files.


### **InputsAndOutputsStructure:**
- Inputs :
    - **InputFile1**                : [OPTIONAL] The first file to be merged. Supported file formats: json, ndjson, csv, or parquet.
    - **InputFile2**                : [OPTIONAL] The second file to be merged. Supported file formats: json, ndjson, csv, or parquet.
    - **MergeType**                 : [OPTIONAL]  Determines the behaviour of the task, either APPEND or CONCATENATE 
    - **OutputFileFormat**          : [OPTIONAL] Target format for conversion of output file (supported formats JSON, CSV, PARQUET).
    - **LogConfigFile**             : [OPTIONAL] This file defines all exception messages and error-handling details for the current task. It is a TOML file containing predefined fields with placeholder values, which will be dynamically replaced at runtime based on the task’s context.
    - **ProceedIfLogExists**        : [OPTIONAL] If the previous task returns a log file and passes it to the current task, this field determines whether the current task should proceed and return the log file at the end of execution, or stop immediately and return the log file. The default value is true.
    - **ProceedIfErrorExists**      : [OPTIONAL] If the current task returns an error, this field determines whether to return the log file and continue to the next task, or to stop the entire rule execution. The default value is true.
    - **LogFile**                   : [OPTIONAL] Map the LogFile from the previous task, to handle errors
    - **OutputFileName**            : [OPTIONAL] This name will be used for the output file. If not provided, it will default to `MergedData`.
- Outputs :
    - **MergedData**       : File that contains the merged data
    - **LogFile**          : File that contains information about errors that have occurred while execution


### **InputsSection:**
1. InputFile1 **(OPTIONAL)**
    - This is a file containing one set of data that has to be merged (Supported file formats: json, ndjson, csv, or parquet).
    - At least one input file (either `InputFile1` or `InputFile2`) must be provided. The task cannot proceed if both are missing.
    - **Sample InputFile1:**
        ```json
        [
            {
                "FieldA": "ValueA",
                "FieldB": "ValueB"
            },
            {
                "FieldA": "ValueC",
                "FieldB": "ValueD"
            }
        ]
        ```

2. InputFile2 **(OPTIONAL)**
    - This is a file containing the second set of data that has to be merged (Supported file formats: json, ndjson, csv, or parquet)
    - At least one input file (either `InputFile1` or `InputFile2`) must be provided. The task cannot proceed if both are missing.
    - **Sample InputFile2:**
        ```json
        [
            {
                "FieldA": "ValueE",
                "FieldB": "ValueF"
            },
            {
                "FieldA": "ValueG",
                "FieldB": "ValueH"
            }
        ]
        ```

3. MergeType: **(OPTIONAL)**

    - MergeType determines how to merge the data from InputFile1 and InputFile2.
    - The value should be either APPEND or CONCATENATE.
    - The default value will be APPEND, if this field is ignored.

    ### **MergeType: APPEND**
    - APPEND merge type merges the rows of both the files.
    - Both InputFile1 and InputFile2 must have the same structure, for them to be merged using this merge type.
    - For example, consider the input files below:
        ```jsonc
        //InputFile1
        [
            {
                "FieldA": "ValueA",
                "FieldB": "ValueB"
            },
            {
                "FieldA": "ValueC",
                "FieldB": "ValueD"
            }
        ]

        //InputFile2
        [
            {
                "FieldA": "ValueE",
                "FieldB": "ValueF"
            },
            {
                "FieldA": "ValueG",
                "FieldB": "ValueH"
            }
        ]
        ```
    - This is how the output will look like:
        ```jsonc
        //MergedData
        [
            {
                "FieldA": "ValueA",
                "FieldB": "ValueB"
            },
            {
                "FieldA": "ValueC",
                "FieldB": "ValueD"
            },
            {
                "FieldA": "ValueE",
                "FieldB": "ValueF"
            },
            {
                "FieldA": "ValueG",
                "FieldB": "ValueH"
            }
        ]
        ```

    ### **MergeType: CONCATENATE**
    - CONCATENATE merge type merges the columns of both the files, based on their position in the list.
    - For example, consider the input files below:
        ```jsonc
        //InputFile1
        [
            {
                "FieldA": "ValueA",
                "FieldB": "ValueB"
            },
            {
                "FieldA": "ValueC",
                "FieldB": "ValueD"
            },
            {
                "FieldA": "ValueI",
                "FieldB": "ValueJ"
            }
        ]

        //InputFile2
        [
            {
                "FieldC": "ValueE",
                "FieldD": "ValueF"
            },
            {
                "FieldC": "ValueG",
                "FieldD": "ValueH"
            }
        ]
        ```
    - This is how the output will look like:
        ```jsonc
        //MergedData
        [
            {
                "FieldA": "ValueA",
                "FieldB": "ValueB",
                "FieldC": "ValueE",
                "FieldD": "ValueF"
            },
            {
                "FieldA": "ValueC",
                "FieldB": "ValueD",
                "FieldC": "ValueG",
                "FieldD": "ValueH"
            },
            {
                "FieldA": "ValueI",
                "FieldB": "ValueJ"
                // No data was added here because a third element is not there in InputFile2
            }
        ]
        ```
4. OutputFileFormat **(OPTIONAL)**
    - Specifies the output file format for conversion.
    - Allowed values: JSON, CSV, PARQUET.
    - **Default:** PARQUET

5. LogConfigFile **(OPTIONAL)**
   - This file defines exception messages and error-handling logic for the current task.
   - It is a TOML file containing predefined fields with placeholders that are dynamically replaced at runtime based on the task’s context.
   - If a placeholder in the TOML file cannot be resolved at runtime, an error will be raised.
   - At the task level, a default file named `LogConfig_default.toml` is used if the user does not provide a custom configuration.
   - For example:
   ```toml
   [MergeData]
   [MergeData.Validation]
   # Log file validation errors
   LogFile.download_failed = "Unable to download the log file from MinIO. Please find more details: {error}"
   ```
   In this example, the {error} placeholder will be replaced with the actual error message at runtime. If the placeholder is invalid or cannot be resolved, the system will raise an error.

    We can also include the from and to dates in the error message for better clarity using the {fromdate} and {todate} placeholders.
  
6. ProceedIfLogExists **(OPTIONAL)**
   - This field is optional, and the default value of ProceedIfLogExists is true.
   - If ProceedIfLogExists is set to true, the task will continue its execution and return the LogFile at the end.
   - If it is set to false and a log file is already present, the task will skip further execution and simply return the existing LogFile.

7. ProceedIfErrorExists **(OPTIONAL)**
    - This field is optional, and the default value of ProceedIfErrorExists is true.
    - If ProceedIfErrorExists is set to true, the task will return the error details as part of the LogFile and continue to the next task.
    - If it is set to false, the error details will be returned, and the entire rule execution will be stopped.
    
8. LogFile **(OPTIONAL)**
    - This field is required only if this task is not the first one in the rule.
    - The LogFile from the previous task must be mapped here to enable error handling.
    - If mapped correctly, and the previous task returns a LogFile, it will be passed to this task. The task’s execution will then be determined based on the value of ProceedIfLogExists.

9. OutputFileName **(OPTIONAL)**
    - This field is optional. If not provided, it will default to `MergedData`.
    - If provided, this name will be used for the output file containing the merged data.

### **OutputsSection:**
1. MergedData
    - File that contains the merged data
2. LogFile
    - This file contains information about errors that may have occurred while processing the conditions
