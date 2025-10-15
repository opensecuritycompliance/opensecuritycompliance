**Purpose**:
The purpose of this task is to check whether the records in the InputFile match the conditions provided in the LogConfigFile. You can configure the task to add a custom error message to the log file based on the provided conditions in the LogConfigFile.

### **InputsAndOutputsStructure:**
- Inputs 

    - **InputFile**: A JSON file containing the response data from the previous task.
     - **LogFile**: Maps the log file from the previous task to handle errors.
    - **LogConfigFile**: Enables custom conditional logging based on the specified output file.
    - **ProceedIfLogExists**: A boolean flag to check if the log file from the previous task exists, determining whether the process should continue.
- Outputs :

    - **OutputFile**: The file containing the response from the previous task, which includes the response data in a JSON structure.
    - **LogFile**                : File that contains information about errors that have occurred while processing the conditions


### **InputsSection:**
1. InputFile **(MANDATORY)**
    - This is a file containing an array of data with which the conditions must be checked from the LogConfigFile
    - To access data from InputFile in LogConfigFile , use `<<inputfile.FieldName>>`
    
    **Sample InputFile:**
    ```json
    [
        {
            "data" : {
                "internalError" : false,
                "unredactedFromSecureObject" : false,
                "errorCode" : "001003",
                "age" : 0,
                "sqlState" : "42000",
                "queryId" : "01bae9e3-0000-e5f4-0008-d6ea00069006",
                "line" : -1,
                "pos" : -1,
                "type" : "COMPILATION"
            },
            "code" : "001003",
            "message" : "SQL compilation error:\nparse error line 1 at position 122 near '<EOF>'.\nsyntax error line 1 at position 122 unexpected '<EOF>'.",
            "success" : false,
            "headers" : null
        }
    ]
    ```
2. LogFile **(Optional)**
    - This field is required only when this task is not the first one in the rule.
    - LogFile from the previous task must be mapped to this to handle errors.
    - If mapped correctly, when the previous task returns a 'LogFile', it will pass it to this task and this task won't be executed.Otherwise if there is no 'LogFile' from the previous task, this task will execute as expected.

3. LogConfigFile: **(MANDATORY)**

    - 'LogConfigFile' file defines the conditions to be checked and specifies the fields that should be evaluated for log generation based on those conditions.

    ### **LogConfigFile Structure:**
    ```toml
    [[ConditionRules]]
        Condition = "EQUALS"  # Specifies the type of condition to apply.
        ConditionField = "<<inputfile.[0].success>>"  # Field extracted from InputFile for evaluation.
        ConditionValue = false  # The expected value for the condition to be met.
        ErrorMessage = "SQL compilation error. Please review the query and try again."  # Custom error message to log if the condition is met.
    ```
    ### **ConditionRules:**
    **(MANDATORY)** ConditionRules specifies the condition data, such as the condition values, and the type of condition for a list of conditions, refer below:
    ```toml
    [[ConditionRules]]
        Condition = "EQUALS"
        ConditionField = "<<inputfile.[0].success>>"
        ConditionValue = false
        ErrorMessage = "SQL compilation error. Please review the query and try again."
    ```
    **Condition types for Condition field:**
    - EMPTY
        - Checks whether ConditionField's value is empty.
    - NOT_EMPTY
        - Checks whether ConditionField's value is not empty.
    - CONTAINS
        - Checks whether ConditionField's value contains ConditionValue as a sub-string.
        - You can also check whether an array or list has ConditionValue as an element in it, or whether the ConditionValue is a key that is available in a key-value object.
    - NOT_CONTAINS
        - Opposite of CONTAINS.
    - REGEX
        - Checks whether ConditionField's value matches the regex pattern given in ConditionValue.
    - EQUALS
        - Checks whether ConditionField's value exactly matches ConditionValue.
    - NOT_EQUALS
        - Checks whether ConditionField's value does not match ConditionValue.
    - LESSER_THAN or LT
        - Checks whether ConditionField's value is lesser than ConditionValue. This will work only on numbers.
    - GREATER_THAN or GT
        - Checks whether ConditionField's value is greater than ConditionValue. This will work only on numbers.
    - LESSER_THAN_OR_EQUALS or LT_EQ
        - Checks whether ConditionField's value is lesser than or equal to ConditionValue. This will work only on numbers.
    - GREATER_THAN_OR_EQUALS or GT_EQ
        - Checks whether ConditionField's value is greater than or equal to ConditionValue. This will work only on numbers.

    ConditionValue is not required for 'EMPTY and NOT_EMPTY' conditions

    **Note:**
    - The fields that you access from InputFile using `<<inputfile.FieldName>>` must not contain spaces
    - For example: `<<inputfile.Created date>>` is invalid. You can use the TransformData task to rename the field without spaces.

4. ProceedIfLogExists: **(Optional)**
- **ProceedIfLogExists**: This field determines whether the next task should execute based on the generated log file.
  - **If `True`** → The task proceeds to the next step, generating both the log file and the output file.  
  - **If `False`** → The task only generates the log file, and the next task will not be executed.



### **OutputsSection:**
1. OutputFile
    - Represents the InputFile that was processed in this task for conditional checks.
2. LogFile
    - This file contains information about errors that may have occurred while processing the conditions
