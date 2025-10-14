The purpose of this task is to convert files between supported formats: JSON, CSV, YAML, TOML, XLSX, XML, and PARQUET. It processes an input file in one of these formats and generates an output file in the specified target format.


- **InputsAndOutputsStructure**: 
    - Inputs :
        - **InputFile**                : [MANDATORY] Source file containing data in formats such as JSON, CSV, YAML, TOML, XLSX, XML, and PARQUET
        - **OutputFileFormat**         : [MANDATORY] Target format for conversion (e.g., JSON, CSV, PARQUET, YAML, TOML, XLSX).
        - **LogConfigFile**            : [OPTIONAL] This file defines all exception messages and error-handling details for the current task. It is a TOML file containing predefined fields with placeholder values, which will be dynamically replaced at runtime based on the task’s context.
        - **ProceedIfLogExists**       : [OPTIONAL] If the previous task returns a log file and passes it to the current task, this field determines whether the current task should proceed and return the log file at the end of execution, or stop immediately and return the log file. The default value is true.
        - **ProceedIfErrorExists**     : [OPTIONAL] If the current task returns an error, this field determines whether to return the log file and continue to the next task, or to stop the entire rule execution. The default value is true.
        - **LogFile**                  : [OPTIONAL] Map the LogFile from the previous task, to handle errors
    - Outputs :
        - **OutputFile**               : The file containing the converted data in the specified OutputFileFormat.
        - **LogFile**                  : File that contains information about errors that have occurred while execution.


- **InputsSection**:
    1. InputFile **(MANDATORY)**
        - Specifies the original data file for conversion.
        - Must be a valid MINIO file path in JSON, CSV, YAML, TOML, XLSX, XML, or PARQUET format.
        - **Sample InputFile:**
        ```json
        [
            {
                "id": 1,
                "name": "Alice",
                "email": "alice@example.com"
            },
            {
                "id": 2,
                "name": "Bob",
                "email": "bob@example.com"
            }
        ]
        ```
    2. OutputFileFormat **(MANDATORY)**
       - Specifies the target file format to convert to.
       - Allowed values: JSON, CSV, PARQUET, YAML, TOML, XLSX.  
       - **Sample OutputFileFormat:** CSV
       
    3. LogConfigFile **(OPTIONAL)**
        - This file defines exception messages and error-handling logic for the current task.
        - It is a TOML file containing predefined fields with placeholders that are dynamically replaced at runtime based on the task’s context.
        - If a placeholder in the TOML file cannot be resolved at runtime, an error will be raised.
        - At the task level, a default file named `LogConfig_default.toml` is used if the user does not provide a custom configuration.
        - For example:
        ```toml
        [ConvertFileFormat]
        [ConvertFileFormat.Exception]
        # Log file related exceptions
        LogFile.download_failed = "Unable to download the log file from MinIO. Please find more details: {error}"
        ```
        In this example, the {error} placeholder will be replaced with the actual error message at runtime. If the placeholder is invalid or cannot be resolved, the system will raise an error.

        We can also include the from and to dates in the error message for better clarity using the {fromdate} and {todate} placeholders.
    
    5. ProceedIfLogExists **(OPTIONAL)**
        - This field is optional, and the default value of ProceedIfLogExists is true.
        - If ProceedIfLogExists is set to true, the task will continue its execution and return the LogFile at the end.
        - If it is set to false and a log file is already present, the task will skip further execution and simply return the existing LogFile.

    6. ProceedIfErrorExists **(OPTIONAL)**
        - This field is optional, and the default value of ProceedIfErrorExists is true.
        - If ProceedIfErrorExists is set to true, the task will return the error details as part of the LogFile and continue to the next task.
        - If it is set to false, the error details will be returned, and the entire rule execution will be stopped.
    
    7. LogFile **(OPTIONAL)**
        - This field is required only if this task is not the first one in the rule.
        - The LogFile from the previous task must be mapped here to enable error handling.
        - If mapped correctly, and the previous task returns a LogFile, it will be passed to this task. The task’s execution will then be determined based on the value of ProceedIfLogExists.


- **OutputsSection**:
    1. OutputFile
        - This file contains the converted data in the target format specified in the OutputFileFormat input.
        - It will store the result of the conversion, such as the data in JSON, CSV, PARQUET, YAML, TOML, or XLSX format.
        - **Sample OutputFile:**
        ```csv
        id,name,email
        1,Alice,alice@example.com
        2,Bob,bob@example.com
        ```

    2. LogFile
        - A file that captures any errors encountered during the execution of the task.
