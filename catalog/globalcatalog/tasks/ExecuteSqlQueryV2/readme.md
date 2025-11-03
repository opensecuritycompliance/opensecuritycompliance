The purpose of this task is to execute the provided SQL query on the given input file(s). The task requires at least one JSON file and an SQL query (defined in a TOML file) as inputs. It produces the resulting data as a JSON file in the output.

### **InputsAndOutputsStructure:**
- Inputs :
    - **InputFile1**                : [MANDATORY] The primary JSON file containing an array of records on which the SQL query must be executed.
    - **InputFile2**                : [OPTIONAL] An optional secondary JSON file containing additional records to be included in the SQL query.
    - **SQLConfig**                 : [MANDATORY] A TOML file containing the SQL query to be executed. Tables named inputfile1 and inputfile2 will be created based on the input files provided.
    - **LogConfigFile**             : [OPTIONAL] This file defines all exception messages and error-handling details for the current task. It is a TOML file containing predefined fields with placeholder values, which will be dynamically replaced at runtime based on the task’s context.
    - **ProceedIfLogExists**        : [OPTIONAL]  If the previous task returns a log file and passes it to the current task, this field determines whether the current task should proceed and return the log file at the end of execution, or stop immediately and return the log file. The default value is true.
    - **ProceedIfErrorExists**      : [OPTIONAL]  If the current task returns an error or if a log file from a previous task is available, this field determines whether to return the log file and continue to the next task, or to stop the entire rule execution. The default value is true.
    - **LogFile**                   : [OPTIONAL]  Map the LogFile from the previous task, to handle errors.
- Outputs :
    - **OutputFile**                : File that contains the result of the SQL Query.
    - **LogFile**                   : File that contains information about errors that have occurred while executing the task.


### **InputsSection:**
1. InputFile1 **(MANDATORY)**
    - This is a JSON file containing an array of data records. These records form the inputfile1 table used in the SQL query.
    
    **Sample InputFile1:**
    ```json
    [
        {
            "name": "projects/some-project/serviceAccounts/firebase-adminsdk@some-project.iam.gserviceaccount.com",
            "projectId": "some-project",
            "email": "firebase-adminsdk@some-project.iam.gserviceaccount.com",
            "displayName": "firebase-adminsdk",
            "description": "Firebase Admin SDK Service Agent"
        },
        {
            "name": "projects/some-project/serviceAccounts/compute@developer.gserviceaccount.com",
            "projectId": "some-project",
            "email": "compute@developer.gserviceaccount.com",
            "displayName": "Compute Engine default service account"
        },
        {
            "name": "projects/some-project/serviceAccounts/test@some-project.iam.gserviceaccount.com",
            "projectId": "some-project",
            "email": "test@some-project.iam.gserviceaccount.com",
            "displayName": "test",
            "description": "test"
        }
    ]
    ```

2. InputFile2 **(OPTIONAL)**
    - This is the optional secondary JSON file containing an array of records. These form the inputfile2 table for use in SQL JOINs or lookups.
    
    **Sample InputFile2:**
    ```json
    [
        {
            "resource": {
                "type": "service_account",
                "labels": {
                    "email_id": "test@some-project.iam.gserviceaccount.com",
                    "project_id": "some-project"
                }
            },
            "timestamp": "2024-09-30T12:07:45.375669895Z",
            "severity": "NOTICE",
            "logName": "projects\/some-project\/logs\/cloudaudit.googleapis.com%2Factivity",
            "receiveTimestamp": "2024-09-30T12:07:46.014628153Z"
        },
        {
            "resource": {
                "type": "service_account",
                "labels": {
                    "project_id": "some-project",
                    "email_id": "test@some-project.iam.gserviceaccount.com"
                }
            },
            "timestamp": "2024-09-30T12:05:13.613207129Z",
            "severity": "NOTICE",
            "logName": "projects\/some-project\/logs\/cloudaudit.googleapis.com%2Factivity",
            "receiveTimestamp": "2024-09-30T12:05:14.605754621Z"
        }
    ]
    ```

3. SQLConfig: **(MANDATORY)**

    - 'SQLConfig' is a TOML file that contains the SQLQuery to be executed.
    - The following tables will be created with the respective data: inputfile1, inputfile2.
    - If only InputFile1 is provided, then only 'inputfile1' table will be created.
    - The output file format can be specified as JSON, CSV, or PARQUET (default is PARQUET if not specified).

    **SQLConfig Structure:**
    ```toml
    SQLQuery = '''
        SELECT
            inputfile1.*,
            CASE 
                WHEN COUNT(inputfile2.timestamp) = 0 THEN NULL
                ELSE json_group_array(
                    json_object(
                        'timestamp', inputfile2.timestamp
                    )
                )
            END AS UsageLogTimestamps
        FROM
            inputfile1
        LEFT JOIN
            inputfile2
        ON
            inputfile1.email = inputfile2.`resource.labels.email_id`
        GROUP BY
            inputfile1.email;
    '''
    # Output file format (Optional - defaults to PARQUET)
    # Supported values: "JSON", "CSV", "PARQUET"
    OutputFileFormat = "PARQUET"
    ```

4. LogConfigFile **(Optional)**
    - This file defines exception messages and error-handling logic for the current task.
    - It is a TOML file containing predefined fields with placeholders that are dynamically replaced at runtime based on the task’s context.
    - If a placeholder in the TOML file cannot be resolved at runtime, an error will be raised.
    
    For example: 
    
    ```toml
    [ExcecuteSQLQuery]

    [ExcecuteSQLQuery.Validation]

        # Log file validation errors
        LogFile.download_failed = "Unable to download the log file from MinIO. Please check the details: {error}"

        # Input file validation errors
        Inputs.empty_or_invalid = "Mandatory input files are missing or invalid. Please check the details: {error}."

        InputFile1.load_failed = "Failed to load InputFile1. Please check the details: {error}."
        InputFile2.load_failed = "Failed to load InputFile2. Please check the details: {error}."

        InputFile1.download_failed = "Unable to download InputFile1 from MinIO. Please check the details: {error}"
        InputFile2.download_failed = "Unable to download InputFile2 from MinIO. Please check the details: {error}"

        SQLConfig.download_failed = "Unable to download the SQLConfig file from MinIO. Please check the details: {error}"
        SQLConfig.validation_failed = "SQLConfig file validation failed. Please check the details: {error}"
        SQLConfig.unsafe_query_detected = "The SQL query contains potentially dangerous keywords (DROP, DELETE, TRUNCATE, ALTER, UPDATE, INSERT). Please review the SQLQuery and remove any unsafe keywords before proceeding."
        SQLConfig.query_execution_failed = "SQL query execution failed. Please check the details: {error}"
        SQLConfig.query_no_output = "The SQL query did not return any output."

        # Upload file errors
        OutputFile.upload_failed = "Unable to upload the output file to MinIO. Please check the details: {error}"
        LogFile.upload_failed = "Unable to upload the log file to MinIO. Please check the details: {error}"

    ```
    
    In this example, the `{placeholder}` will be replaced with the actual value at runtime. If the placeholder is invalid or cannot be resolved, the system will raise an error.

    We can also include the from and to dates in the error message for better clarity using the {fromdate} and {todate} placeholders.

5. ProceedIfLogExists **(Optional)**
   - This field is optional, and the default value of ProceedIfLogExists is true.
   - If ProceedIfLogExists is set to true, the task will continue its execution and return the LogFile at the end.
   - If it is set to false and a log file is already present, the task will skip further execution and simply return the existing LogFile.

6. ProceedIfErrorExists **(Optional)**
   - This field is optional, and the default value of ProceedIfErrorExists is true.
   - If ProceedIfErrorExists is set to true, the task will return the error details as part of the LogFile and continue to the next task.
   - If it is set to false, the error details will be returned, and the entire rule execution will be stopped.

7. LogFile **(Optional)**
    - This field is required only when this task is not the first one in the rule.
    - LogFile from the previous task must be mapped to this to handle errors.
    - If mapped correctly, when the previous task returns a 'LogFile', it will pass it to this task and this task won't be executed.Otherwise if there is no 'LogFile from the previous task, this task will execute as expected.


### **OutputsSection:**
1. OutputFile
    - This file contains the results of the SQL query executed using the given input file(s).
2. LogFile
    - This file contains information about any errors that may have occurred during task execution.