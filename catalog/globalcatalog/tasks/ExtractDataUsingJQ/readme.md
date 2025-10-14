The purpose of this task is to extract data from the InputFile based on the provided JQ filter/expression. The task expects a JSON file and JQ filter/expression as inputs, and provides the extracted data as JSON file in the output.

### **InputsAndOutputsStructure:**
- Inputs :
    - InputFile       : [MANDATORY] The file that contains the records in which the JQ expression must be executed
    - JQConfig        : [OPTIONAL]  The TOML file that contains the JQExpression & OutputMethod as an alternative to the below individual inputs
    - JQExpression    : [OPTIONAL]  The JQ filter/expression that must be executed on the InputFile data
    - OutputMethod    : [OPTIONAL]  Specifies whether to consider all outputs from the JQ expression, or only the first one (default)
    - LogFile         : [OPTIONAL]  Map the LogFile from the previous task, to handle errors
- Outputs :
    - OutputFile      : File that contains the output of the JQ expression
    - LogFile         : File that contains information about errors that have occurred while executing the task


### **InputsSection:**
1. InputFile **(MANDATORY)**
    - This is a file containing an array of data with which the JQ filter/expression must be executed

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

2. JQConfig: **(OPTIONAL)**

    - 'JQConfig' file contains the JQExpression & OutputMethod in the TOML structure, as an alternative to the below individual inputs
    - You must give either JQConfig or the JQExpression as user input
    - In cases where both inputs are given, task execution will be aborted and LogFile will be produced

    **JQConfig Structure:**
    ```toml
    [JQConfig]
    JQExpression = ".[].repositories[]" # [MANDATORY] Contains the JQ filter/expression that must be executed on the InputFile data
    OutputMethod = "ALL" # [OPTIONAL] (AllowedValues: FIRST, ALL) Specifies whether to consider all outputs from the JQ expression, or only the first one
    ```

    **Note:**
    - The the above fields behave the same as the individual user inputs below. Please refer below for examples.

3. JQExpression: **(OPTIONAL)**

    - This is a STRING input that contains the JQ filter/expression that must be executed on the InputFile data
    - The output provided by the JQ filter/expression MUST be either a JSON object, or an array of JSON objects
    - Example: `.[].repositories[]`
    - [Refer the documentation](https://jqlang.github.io/jq/manual/#basic-filters) for more info

4. OutputMethod: **(OPTIONAL)**

    - This is a STRING input that specifies whether to consider all outputs from the JQ expression, or only the first one (default)
    - This input accepts the following values: `'FIRST' & 'ALL'`
    - If no input is provided, then the default value 'FIRST' is used

    ### **OutputMethod - FIRST:**
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

    ### **OutputMethod - ALL:**
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

5. LogFile **(Optional)**
    - This field is required only when this task is not the first one in the rule.
    - LogFile from the previous task must be mapped to this to handle errors.
    - If mapped correctly, when the previous task returns a 'LogFile', it will pass it to this task and this task won't be executed.Otherwise if there is no 'LogFile from the previous task, this task will execute as expected.


### **OutputsSection:**
1. OutputFile
    - This file contains the output of the JQ expression
2. LogFile
    - This file contains information about errors that may have occurred while executing the task
