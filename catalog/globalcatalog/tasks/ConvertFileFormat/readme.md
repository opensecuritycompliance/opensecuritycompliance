
- **Name**: ConvertFileFormat


- **Purpose**: The purpose of this task is to convert files between supported formats: JSON, CSV, YAML, TOML, XML and PARQUET. It processes an input file in one of these formats and generates an output file in the desired format from the same set of formats.


- **InputsAndOutputsStructure**:
    - Inputs :
        InputFile :  <<MINIO_FILE_PATH>>
        OutputFileFormat:  # (Supported format for conversion: json, yaml, toml, csv, xml, parquet)
        LogFile :  <<MINIO_FILE_PATH>>
        OutputFileName: # This name will be used for the output file
    - Outputs :
        OutputFile : <<MINIO_FILE_PATH>>
        LogFile :  <<MINIO_FILE_PATH>>


- **InputsSection**:
    1. LogFile (Optional)
        - This field is required only when this task is not acting as task1 in the rule.
        - Generally when the previous task has 'LogFile' it will pass that logfile to this task and If the 'LogFile' is empty, it will process 'ConvertFileFormat' task else will check other required inputs exist if they do not will simply pass this previous task 'LogFile' to 'ConvertFileFormat' task 'LogFile'.

    2. InputFile (Mandatory)
        - This field specifies the source file that contains the data to be converted.
        - The input file must be in one of the following supported formats: JSON, CSV, YAML, TOML, XML, or PARQUET.
        - A valid MINIO file path must be provided for the conversion process to begin

    3. OutputFileFormat (Mandatory)
        - This field defines the target format to which the input file should be converted.
        - It determines how the data in the InputFile will be structured in the output file.
        - The target format must be one of the following: JSON, CSV, YAML, TOML, or PARQUET.

    4. OutputFileName (Optional) 
        - If OutputFileName is specified, the output file will use that name; otherwise, it defaults to `OutputFile`.

- **OutputsSection**:
    1. OutputFile
        - This file contains the converted data in the target format specified in the OutputFileFormat input.
        - It will store the result of the conversion, such as the data in JSON, CSV, YAML, TOML, or PARQUET format.
        
    2. LogFile
        - This file captures log information during the conversion proces.
        - It can include error messages or debug information to help identify issues, if any arise during the task execution.
