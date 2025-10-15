The purpose of this task is to merge two files given as input, into one consolidated file. This task has two functionalities:
- APPEND: Merges the rows from both files. This is the default behaviour.
- CONCATENATE: Merges the columns from both files.

### **InputsAndOutputsStructure:**
- Inputs :
    - InputFile1       : [MANDATORY] The first file that has to be merged
    - InputFile2       : [MANDATORY] The second file that has to be merged
    - MergeType        : [OPTIONAL]  Determines the behaviour of the task, either APPEND or CONCATENATE
    - LogFile          : [OPTIONAL]  Map the LogFile from the previous task, to handle errors
- Outputs :
    - MergedData       : File that contains the merged data
    - LogFile          : File that contains information about errors that have occurred while execution


### **InputsSection:**
1. InputFile1 **(MANDATORY)**
    - This is a file containing one set of data that has to be merged
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

2. InputFile2 **(MANDATORY)**
    - This is a file containing the second set of data that has to be merged
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

4. LogFile **(Optional)**
    - This field is required only when this task is not the first one in the rule.
    - LogFile from the previous task must be mapped to this to handle errors.
    - If mapped correctly, when the previous task returns a 'LogFile', it will pass it to this task and this task won't be executed.Otherwise if there is no 'LogFile from the previous task, this task will execute as expected.


### **OutputsSection:**
1. MergedData
    - File that contains the merged data
2. LogFile
    - This file contains information about errors that may have occurred while processing the conditions
