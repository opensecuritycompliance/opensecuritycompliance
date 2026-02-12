**Purpose**: The purpose of this task is to check whether the records in the InputFile matches the conditions provided in the ConditionConfig file. You can configure the task to update certain fields based on different conditions, and / or split them into two files for processing it further. The output contains 2 files: 'MatchedConditionFile' and UnmatchedConditionFile', that are in 'parquet' format.

### **InputsAndOutputsStructure:**
- Inputs :
    - **InputFile**                        : [MANDATORY] The file that contains the records in which the condition must be checked
    - **ConditionConfig**                  : [MANDATORY] The file that contains the conditions to check, and the field update data
    - **CustomInputs**                     : [OPTIONAL]  This file contains any dynamic inputs that you may want to pass, to process the conditions
    - **InputFileValidationConfig**        : [OPTIONAL]  This field is used to check if required fields are present in the input file.
    - **LogConfig**                        : [OPTIONAL]  This file defines all exception messages and error-handling details for the current task. It is a TOML file containing predefined fields with placeholder values, which will be dynamically replaced at runtime based on the task’s context.
    - **OutputFileFormat**                 : [OPTIONAL] Target format for conversion of output file (supported formats JSON, CSV, PARQUET).
    - **ProceedIfLogExists**               : [OPTIONAL]  If the previous task returns a log file and passes it to the current task, this field determines whether the current task should proceed and return the log file at the end of execution, or stop immediately and return the log file. The default value is true.
    - **ProceedIfErrorExists**             : [OPTIONAL]  If the current task returns an error or if a log file from a previous task is available, this field determines whether to return the log file and continue to the next task, or to stop the entire rule execution. The default value is true.
    - **LogFile**                          : [OPTIONAL]  Map the LogFile from the previous task, to handle errors
- Outputs :
    - **MatchedConditionFile**   : File that contains records from InputFile that passed the condition
    - **UnmatchedConditionFile** : File that contains records from InputFile that did not pass the condition
    - **LogFile**                : File that contains information about errors that have occurred while processing the conditions


### **InputsSection:**
1. InputFile **(MANDATORY)**
    - This is a file containing an array of data with which the conditions must be checked from the ConditionConfig file
    - To access data from InputFile in ConditionConfig file, use `<<inputfile.FieldName>>`
    
    **Sample InputFile:**
    ```json
    [
        {
            "id": "SNYK-DEBIAN12-OPENSSH-1555766",
            "title": "Access Restriction Bypass",
            "createdDate": "04/01/2023 05:44",
            "type": "vuln",
            "isPatchable": false,
            "security": "high",
            "cvssScore": 8.8,
            "affectedSystems": [
                "Debian 12",
                "OpenSSH 8.9",
                "OpenSSH 9.0"
            ],
            "relatedExploits": [
                {
                    "exploitId": "EXPLOIT-001",
                    "description": "Exploit for bypassing access restrictions in OpenSSH.",
                    "severity": "critical",
                    "discoveredDate": "03/15/2023"
                },
                {
                    "exploitId": "EXPLOIT-002",
                    "description": "Remote code execution vulnerability in OpenSSH.",
                    "severity": "high",
                    "discoveredDate": "02/20/2023"
                }
            ]
        }
    ]
    ```

2. ConditionConfig: **(MANDATORY)**

    - 'ConditionConfig' file contains the conditions to check, and the data determining the fields that has to be updated based on condition

    ### **ConditionConfig Structure:**
    ```toml
    # [[ConditionRules]] -> [MANDATORY] Specifies the condition data, such as the condition values, and the type of condition
    #   ConditionLabel   -> Unique name for the condition
    #   Condition        -> Type of condition
    #   ConditionField   -> Field path from the InputFile to check with the condition
    #   ConditionValue   -> Static/dynamic value that must be compared with the value of ConditionField
    #   DateFormat       -> Specific for date related conditions, this field holds the format of the date value in ConditionField and ConditionValue
    #  - You can have as many ConditionRules as necessary

    # [ConditionRulesConfig] -> [MANDATORY]
    #   ConditionsCriteria   -> CEL expression with ConditionLabel(s) that determines the splitting of the InputFile

    # [[ConditionFieldUpdates]]      -> [OPTIONAL] Can be used to update fields in the InputFile based on provided CEL expression in ConditionsCriteria
    #   ConditionsCriteria           -> CEL expression with ConditionLabel(s) that determine whether the current record from InputFile must be updated with PASS / FAIL values
    #   [ConditionFieldUpdates.PASS] -> Values to update in the record, if ConditionsCriteria passes
    #   [ConditionFieldUpdates.FAIL] -> Values to update in the record, if ConditionsCriteria fails
    ```

    **Note:**
    For ConditionField, ConditionValue and ConditionFieldUpdates.PASS/FAIL fields:
    - Use `<<inputfile.FieldName>>` or `{{inputfile.FieldName}}` to access data from InputFile
    - Use `<<custominputs[index].FieldName>>` or `{{custominputs[index].FieldName}}` to access data from CustomInputs file.
    - All of the placeholders use JQ library to extract data. So you can also use placeholders like `{{custominputs[].FieldName}}` to extract the values of `"FieldName"` from all elements as a list

    ### **ConditionRules:**
    **(MANDATORY)** ConditionRules specifies the condition data, such as the condition values, and the type of condition
    For a list of conditions, refer below:
    ### **Common Conditions:**
    ```toml
    [[ConditionRules]]
        ConditionLabel = "check_patchable"
        Condition = "EQUALS"
        ConditionField = "<<inputfile.isPatchable>>"
        ConditionValue = true # Here you can specify the value from the data file similar to 'ConditionField'. Eg: "<<inputfile.title>>"
    ```
    **Condition types for Condition field:**
    - EMPTY
        - Checks whether ConditionField's value is empty.
    - NOT_EMPTY
        - Checks whether ConditionField's value is not empty.
    - CONTAINS
        - Checks whether ConditionField's value contains ConditionValue as a sub-string.
        - You can also check whether an array or list has ConditionValue as an element in it, or whether the ConditionValue is a key that is available in a key-value object.
        - The CONTAINS condition can also be used to check whether a list A (from 'ConditionField/ConditionValue' field) has all of the elements in another list B (from 'ConditionValue/ConditionField' field).
    - NOT_CONTAINS
        - Opposite of CONTAINS.
    - CONTAINS_ANY
        - Checks whether a list A (from 'ConditionField/ConditionValue' field) has any of the elements in another list B (from 'ConditionValue/ConditionField' field).
    - REGEX
        - Checks whether ConditionField's value matches the regex pattern given in ConditionValue.
        - Use single-quotes ('') to enclose the REGEX pattern in the 'ConditionValue' field. Eg: `ConditionValue = '[a-zA-Z\s]'`
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
    - NUMBER_RANGE
        - Checks whether ConditionField's value falls within the range provided in ConditionValue. Refer below for syntax.

    ConditionValue is not required for 'EMPTY and NOT_EMPTY' conditions

    **ConditionValue SYNTAX for NUMBER_RANGE:**
    - `<start-value>:<end-value>` - sets range from start value to end value. Eg: `1:3`
    - `<start-value>:` - sets start value as minimum value. Eg: `1:`
    - `:<end-value>` - sets end value as maximum value Eg: `:3`

    **Visualizing the Condition's Evaluation:**
    - You can visualize that the condition will be evaluated like this: `ConditionField [ConditionType] ConditionValue`
    - For example, consider:
        - Value of ConditionField (from InputFile or CustomInputs) : `35`
        - ConditionValue                                           : `33`
        - Condition                                                : `LESSER_THAN`
    - This can be visualized as: `35 [LESSER_THAN] 33` or `35 < 33`, which would evaluate to `false`

    ### **CEL Condition:**
    ```toml
    [[ConditionRules]]
        ConditionLabel = "cel_check"
        Condition = "CEL_CONDITION"
        ConditionValue = "<<inputfile.isPatchable>> && <<inputfile.createdDate>> != ''"
    ```
    **Note:**
    - You can give a CEL Expression as ConditionValue, and you can omit the 'ConditionField' completely in this case
    - The fields that you access from InputFile or CustomInputs using `<<inputfile.FieldName>>` or `<<custominputs[index].InputName>>` must not contain spaces
    - For example: `<<inputfile.Created date>>` is invalid. You can use the TransformData task to rename the field without spaces.

    ### **Date Conditions:**
    ```toml
    [[ConditionRules]]
        ConditionLabel = "check_date"
        Condition = "FROM_DATE_OFFSET" 
        ConditionField = "<<inputfile.createdDate>>"
        DateFormat = "%m/%d/%Y %H:%M" # refer the below section
        ConditionValue = "-30d" # not required for 'FROM_RULE_DATE, TO_RULE_DATE and RULE_DATE_RANGE' conditions
    ```
    **DateFormat:**
    - DateFormat is optional
    - You can parse the date values using one of the following two methods:
        1. Specify the date format manually
            - `DateFormat = "%m/%d/%Y %H:%M" # see the 'Reference Table for DateFormat' for more information`
        2. Automatically detect the date format
            - `DateFormat.IsDayFirst = false # Determines whether to prioritize day (True) or month (False) in a date such as: 2012-1-9`
            - The above value is used as default if DateFormat is not mentioned
            - It is recommended to manually specify the DateFormat if the date value doesn't contain a 4-digit year, as detection can be inconsistent in this case
            - **Example: 2012-1-9**
                - `IsDayFirst = true`
                    - Year  - 2012
                    - Day   - 01
                    - Month - 09
                - `IsDayFirst = false`
                    - Year  - 2012
                    - Day   - 09
                    - Month - 01

    **DATE Condition types for Condition field:**

    **Common Date Conditions:**
    - FROM_DATE          
        - Checks whether ConditionField's date comes later than the ConditionValue date. The date value must be in the same format as DateFormat.
    - TO_DATE            
        - Checks whether ConditionField's date comes earlier than the ConditionValue date. The date value must be in the same format as DateFormat.
    - DATE_RANGE         
        - Checks whether ConditionField's date falls within the range. Refer '**ConditionValue Syntax for DATE_RANGE**' below.

    **ConditionValue Syntax for DATE_RANGE:**
    - `<start-date>-><end-date>` - sets range from start date to end date. Eg: `02/20/2023 19:33->03/20/2023 00:00`
    - `<start-date>->now` - sets range from start date to current date. Eg: `02/20/2023 19:33->now`
    - `<start-date>->` - considers every date after the start date. Eg: `02/20/2023 19:33->`
    - `now-><end-date>` - sets range from current date to end date. Eg: `now->04/20/2025 19:33`
    - `-><end-date>` - considers every date before the end date. Eg: `->04/20/2025 19:33`
    - `<start-date>` and `<end-date>` must be in the same format as DateFormat
    
    **Conditions based on Rule FromDate and ToDate:**
    - FROM_RULE_DATE     
        - Checks whether ConditionField's date comes later than the FromDate value from the rule inputs.
    - TO_RULE_DATE       
        - Checks whether ConditionField's date comes earlier than the ToDate value from the rule inputs.
    - RULE_DATE_RANGE    
        - Checks whether ConditionField's date falls within the FromDate and ToDate values from the rule inputs.

    **Date Offset Conditions:**
    - FROM_DATE_OFFSET   
        - Checks whether ConditionField's date comes later than the ConditionValue delta string.
        - ConditionValue must be a Delta String. Refer '**Delta String Syntax**' below.
    - TO_DATE_OFFSET     
        - Checks whether ConditionField's date comes earlier than the ConditionValue delta string.
        - ConditionValue must be a Delta String. Refer '**Delta String Syntax**' below.
    - DATE_OFFSET_RANGE  
        - Checks whether ConditionField's date falls within the range. Refer '**ConditionValue Syntax For DATE_OFFSET_RANGE**' below.
    
    **Delta String Syntax:**
    - `<years>y <months>m <days>d <hours>H <minutes>M <seconds>S` - Sets date offset after current date
        - Eg: `"1y 5d"` represents the date/time 1 year and 5 days from today.
    - `- <years>y <months>m <days>d <hours>H <minutes>M <seconds>S` - Use the (-) minus symbol at the beginning to set date offset before current date
        - Eg: `"- 2d 1H"` represents the date/time 2 days and 1 hour ago.

    **ConditionValue Syntax For DATE_OFFSET_RANGE:**
    - `<delta-string>:now` - Considers date starting from the specified offset, to current date
        - Example: `-5d:now` - Assuming current date is: Aug 28 2024, this range considers from Aug 23 2024 to Aug 28 2024
    - `:<delta-string>` - Considers and date before the offset specified
        - Example: `5d:` - Assuming current date is: Aug 28 2024, this range considers any date on or later than Sep 02 2024
    - `now:<delta-string>` - Considers date starting from current date, to the offset specified after the current date
        - Example: `now:5d` - Assuming current date is: Aug 28 2024, this range considers from Aug 28 2024 to Sep 02 2024
    - `now:<delta-string>` - Considers date starting from current date, to the offset specified after the current date
        - Example: `:-5d` - Assuming current date is: Aug 28 2024, this range considers any date on or before Aug 23 2024

    **Note:**
    - For ConditionValue, you can also mention addition/subtraction expressions like `"<<inputfile.createdDate>> - 30d"` and `"<<inputfile.createdDate>> + 5d"`, to calculate date using data from InputFile
        - The left operand must be a date in the provided DateFormat, and the right operand must be of the 'Delta String Syntax' above
    - For '**Conditions based on Rule FromDate and ToDate**', you can ignore the ConditionValue field, as we will fetch them from the rule FromDate & ToDate
    
    **'now' & 'current_date' Keywords:**
    - For ConditionField & ConditionValue, you can mention 'now' to set the value to current date & time
    - For ConditionField and ConditionValue, you can use the these keywords to set the value to current date & time (`'now'`), or just the date (`'current_date'`)
    - You can use `'current_date'` as an alternative to the `'now'` keyword used in the above examples
    - The `'now'` keyword sets the current date along with current time, such as: `2025-05-13T11:36:10`
    - The `'current_date'` keyword sets the current date, but the time is always set to zero, such as: `2025-05-13T00:00:00`

    ### **ConditionRulesConfig:**
    **(MANDATORY)** Use ConditionRulesConfig to specify which conditions must pass or fail, to collectively consider the condition outcome (i.e which records should go inside MatchedConditionFile and which should go into UnmatchedConditionFile)
    ```toml
    [ConditionRulesConfig]
        ConditionsCriteria = "!check_patchable && condition.check_date"
    ```
    **ConditionsCriteria SYNTAX:**
    - **ConditionsCriteria** is a CEL Expression, with the criteria to consider for the final outcome
    - You can use the syntax: `condition.[condition_label]`, where `condition_label` is the 'ConditionLabel' value of any declared 'ConditionRules' in the ConditionConfig file
    - To avoid splitting the InputFile, you can mention `true` to add all records into the MatchedConditionFile, or `false` to add them to UnmatchedConditionFile instead
    - You can also mention `[condition_label]` instead of `condition.[condition_label]`, but the later one is more error-safe
        - For example, assume the condition `check_date` returns an error:
            - If you use `check_patchable && check_date`, it will return error, regardless of the result of `check_patchable` condition 
            - If you use `check_patchable && condition.check_date` instead, it will return error only if `check_patchable` evaluates to `true`. If it evaluates to `false`, it doesn't go further to check the `condition.check_date` condition, since for the `AND` operator, both operators must be `true`
    - Also if you want to use CEL functions such as 'has', you need to use the `condition.[condition_label]` syntax only, for example: `has(conditions.check_date)`

    - **JSON STRUCTURE OF ConditionsCriteria CEL ENVIRONMENT:**
        ```jsonc
        {
            "check_patchable": true, // value depends based on whether the condition passed (true) or failed (false)
            "cel_check": false,
            // Conditions that were NOT evaluated successfully (i.e some exception occurred due to user/task errors), will not be added to the environment
            "conditions": { // Contains a copy of conditions as above, but inside the 'conditions' object.
                "check_patchable": true,
                "cel_check": false
            }
        }
        ```

    ### **ConditionFieldUpdates:**
    **(OPTIONAL)** You can use ConditionFieldUpdates to add or update values in the data based on the condition status.
    ```toml
    [[ConditionFieldUpdates]]
        ConditionsCriteria = "!check_patchable && !condition.check_date"
        [ConditionFieldUpdates.PASS]
            # Values to update in OutputFile, if condition passes
            Result = "NOT_PATCHABLE"
            Reason = "Not patchable, but not created within 30 days"
            RecordID = "<<custominputs[index].InputName>>"
            # Add more fields as needed
        [ConditionFieldUpdates.FAIL]
            # Values to update in OutputFile, if condition fails
            Result = "PATCHABLE"
            Reason = "Patchable and not created within 30 days"

    [[ConditionFieldUpdates]]
        ConditionsCriteria = "!check_patchable && condition.check_date"
        [ConditionFieldUpdates.PASS]
            Result = "NOT_PATCHABLE_CREATED_WITHIN_30DAYS"
            Reason = "Not patchable and created within 30 days"
    ```

    **Note:**
    - Each ConditionFieldUpdates must have values for both, or either of `ConditionFieldUpdates.PASS` and `ConditionFieldUpdates.FAIL` fields
    - You can access InputFile (`<<inputfile.FieldName>>`) and CustomInputs (`<<custominputs[index].InputName>>`) in any of the fields in ConditionFieldUpdates.PASS and ConditionFieldUpdates.FAIL
    - You can add as many ConditionFieldUpdates as necessary

    ### **Reference Table for DateFormat:**
    [https://www.geeksforgeeks.org/how-to-format-date-using-strftime-in-python/](https://www.geeksforgeeks.org/how-to-format-date-using-strftime-in-python/)
    
    | Directive or Format Code | Returned Value                                       | Example                              |
    |--------------------------|------------------------------------------------------|--------------------------------------|
    | %Y                       | Full year with century                               | 2021, 2022                           |
    | %y                       | Year without century with zero padded value          | 00, 01, …, 21, 22, …, 99             |
    | %-y                      | Year without century                                 | 0, 1, …, 99                          |
    | %m                       | Month with zero padded value                         | 01-12                                |
    | %-m                      | Month without zero padded value                      | 1-12                                 |
    | %B                       | Full month name                                      | January, February, …, December       |
    | %b                       | Short form of month                                  | Jan, Feb, …, Dec                     |
    | %A                       | Full weekday name                                    | Sunday, Monday, …                    |
    | %a                       | Short form of weekday name                           | Sun, Mon, …                          |
    | %w                       | Weekday as decimal value                             | 0-6                                  |
    | %d                       | Days with zero padded value                          | 01-31                                |
    | %-d                      | Days with decimal value                              | 1-31                                 |
    | %H                       | Hour (24-hour clock) as a zero-padded value          | 00-23                                |
    | %-H                      | Hour (24-hour clock) without zero-padded value       | 0, 1, …, 23                          |
    | %I                       | Hour (12-hour clock) as a zero-padded value          | 01-12                                |
    | %-I                      | Hour (12-hour clock) without zero-padded value       | 1-12                                 |
    | %M                       | Mins with zero-padded                                | 00-59                                |
    | %-M                      | Mins without zero padded value                       | 0-59                                 |
    | %S                       | Secs with zero padded value                          | 00-59                                |
    | %-S                      | Secs without zero padded value                       | 0-59                                 |
    | %f                       | Micro Secs with zero-padded value                    | 000000 – 999999                      |
    | %p                       | Locale’s AM or PM                                    | AM/PM                                |
    | %j                       | Day of the year with zero padded value               | 001-366                              |
    | %-j                      | Day of the year without zero padded value            | 1-366                                |
    | %z                       | UTC offset in the form +HHMM or -HHMM                |                                      |
    | %Z                       | Time zone name                                       |                                      |
    | %C                       | Locale’s appropriate date and time                   | Fri Apr 02 02:09:07 2020             |
    | %x                       | Locale’s appropriate date                            | 02/04/22                             |
    | %X                       | Locale’s appropriate time                            | 02:04:22                             |
    | %W                       | Week number of the year. Monday as first day of week | 00-53                                |
    | %U                       | Week number of the year. Sunday as first day of week | 00-53                                |


3. CustomInputs: **(Optional)**
    - The 'CustomInputs' file contains any dynamic inputs that you may want to pass, to process the conditions. This file could be a static file, or it could be a file that comes from one of the previous tasks.
    - To access data from CustomInputs file in ConditionConfig file, use `<<custominputs.FieldName>>`
    - Since all placeholders use JQ expression, you can use placeholders like `<<custominputs[].Name>>` to extract the values of `"Name"` field from all elements as a list

    **Sample CustomInputs file:**

    ```json
    [
        {
            "ResourceID": "user@email.com",
        }
    ]
    ```
    **Note:** The 'CustomInputs' file must be an array with one or more elements.
    
4. InputFileValidationConfig **(OPTIONAL)**
    - This field is used to check if required fields are present in the input file.
    - If any required fields are missing, an error will be returned.
    - You can also use it to remove duplicate records based on selected fields.

    ```json
    [
        {
            "FileName": "InputFile",
            "RequiredFields": ["Field1", "Field2"],
            "RemoveDuplicates": true
        },
        {
            "FileName": "CustomInputs",
            "RequiredFields": ["Field1", "Field2"],
            "RemoveDuplicates": true
        }
    ]
    ```

5. LogConfig **(OPTIONAL)**
    - This file defines exception messages and error-handling logic for the current task.
    - It is a TOML file containing predefined fields with placeholders that are dynamically replaced at runtime based on the task’s context.
    - If a placeholder in the TOML file cannot be resolved at runtime, an error will be raised.
    - At the task level, a default file named `LogConfig_default.toml` is used if the user does not provide a custom configuration.
    - For example:
    ```toml
    [CheckCondition]
    
    [CheckCondition.Inputs]
        ############ LogFile EXCEPTIONS ############
        LogFile.download_error = "Unable to download the log file from MinIO. Please find more details: {error}"
    ```
    In this example, the `{error}` placeholder will be replaced with the actual error message at runtime. If the placeholder is invalid or cannot be resolved, the system will raise an error.

    We can also include the from and to dates in the error message for better clarity using the {fromdate} and {todate} placeholders.

6. OutputFileFormat **(OPTIONAL)**
    - Specifies the output file format for conversion.
    - Allowed values: JSON, CSV, PARQUET.
    - **Default:** PARQUET
  
7. ProceedIfLogExists **(OPTIONAL)**
    - This field is optional, and the default value of ProceedIfLogExists is true.
    - If ProceedIfLogExists is set to true, the task will continue its execution and return the LogFile at the end.
    - If it is set to false and a log file is already present, the task will skip further execution and simply return the existing LogFile.

8. ProceedIfErrorExists **(OPTIONAL)**
    - This field is optional, and the default value of ProceedIfErrorExists is true.
    - If ProceedIfErrorExists is set to true, the task will return the error details as part of the LogFile and continue to the next task.
    - If it is set to false, the error details will be returned, and the entire rule execution will be stopped.
    
9. LogFile **(OPTIONAL)**
    - This field is required only if this task is not the first one in the rule.
    - The LogFile from the previous task must be mapped here to enable error handling.
    - If mapped correctly, and the previous task returns a LogFile, it will be passed to this task. The task’s execution will then be determined based on the value of ProceedIfLogExists.


### **OutputsSection:**
1. MatchedConditionFile
    - This file contains records from InputFile that passed the condition
2. UnmatchedConditionFile
    - This file contains records from InputFile that did not pass the condition
3. LogFile
    - This file contains information about errors that may have occurred while processing the conditions
