- **Name**: ExtractData

- **Purpose**: The purpose of this task is to automate data extraction from structured files. It allows users to extract specific data points programmatically by specifying an extraction path (ExtractPath) within the input file (DataFile)

- **InputsAndOutputsStructure**:
    - Inputs :
      DataFile: "<<MINIO_FILE_PATH>>"
      ExtractPath: "<<PATH_TO_BE_EXTRACTED>>"
      LogFile: "<<MINIO_FILE_PATH>>"

    - Outputs :
      OutputFile : <<MINIO_FILE_PATH>>
      LogFile : <<MINIO_FILE_PATH>>

- **InputsSection**:

    1. LogFile (Optional)
        - This field is required only when this task is not acting as task 1 in the rule.
        - Generally when the previous task has 'LogFile' it will pass that logfile to this task, and If the 'LogFile' is empty, it will process the 'ExtractData' task; else, it will check if other required inputs exist; if they do not, it will simply pass this previous task 'LogFile' to the 'ExtractData' task 'LogFile'.

    2. DataFile (Mandatory)
        - This field is the primary input file from which the data will be extracted.
        - It must be a structured file, such as JSON, that allows navigation of the path specified in ExtractPath.
        - The DataFile must always be provided, as it forms the base for the ExtractData operation.

    3. ExtractPath (Mandatory)
        - This field specifies the path within the DataFile to extract the desired data.
        - The path must follow a valid JSON navigation format (e.g., # array -> "0.items.0.dataItem" object -> ""data.items.dataItem"").
        - It directs the task to locate and extract specific data points from the DataFile.

- **OutputsSection**:

    1. OutputFile

        - This file contains the extracted data from DataFile based on the specified ExtractPath.

    2. LogFile

        - If any errors arise in the task, then this will catch all the errors.
