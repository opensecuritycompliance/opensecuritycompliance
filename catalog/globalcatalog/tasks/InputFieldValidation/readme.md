**Purpose**:
The purpose of this task is to validate whether each record in the InputFile contains all the required fields specified in the RequiredField list. If any required field is missing, the task will log an appropriate error message.

### **InputsAndOutputsStructure:**
- Inputs 
    - InputFile     : A file containing records that need validation against required fields.
    - RequiredField : The required fields that must be present in each record of the InputFile.
    - LogFile       :  Maps the log file from the previous task to handle errors.
- Outputs :
    - ValidDataFile : File that contains records from InputFile that passed the condition
    - LogFile       : File that contains information about missing fields in the records that have occurred while processing the conditions.

### **InputsSection:**
1. InputFile **(MANDATORY)**
    - This file contains an array of records that need to be validated against the required fields.
    - Each record in this file must contain the fields specified in RequiredField.
    - The validation process ensures that no required fields are missing.
    
    **Sample InputFile:**
    ```json
    [
        {
            "Priority": "Low",
            "SLAInDays": 10
        },
        {
            "PriorityTest": "Medium",
            "SLA": 5
        },
        {
            "PriorityTest": "High",
            "SLAInDays": 3
        }
    ]
    ```

2. RequiredFields: **(MANDATORY)**
    - An array of field names that must be present in each record of InputFile.
    - If any record is missing one or more of these required fields, it will be logged as an error.

    **Example RequiredField**
    ["Priority", "SLAInDays"]
   
    **Validation Behaviour**
    Given the above InputFile and RequiredFields, the validation process would log errors for missing fields:
        Required Fields: Priority, SLAInDays.
        Following records Required fields are missing:
        Missing field(s) in Record 2: Priority, SLAInDays
        Missing field(s) in Record 3: Priority


3. LogFile **(Optional)**
    - This field is required only when this task is not the first one in the rule.
    - LogFile from the previous task must be mapped to this to handle errors.
    - If mapped correctly, when the previous task returns a 'LogFile', it will pass it to this task and this task won't be executed.Otherwise if there is no 'LogFile' from the previous task, this task will execute as expected.


### **OutputsSection:**
1. MatchedConditionFile
    - This file is generated only if all records in InputFile contain the required fields specified in RequiredField.
    - If at least one record is missing a required field, this file will not be produced.
2. LogFile
    - This file is generated if any records in InputFile are missing required fields.
    - It contains details about the missing fields and the index of the affected records.