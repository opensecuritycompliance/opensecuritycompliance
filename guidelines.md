# Coding guidelines

## ComplianceCow Specific Guidelines

1.  **File Format**: 
    -   If your rule generates a file, consider exporting it in `Parquet` format. This format is advantageous as it handles data size efficiently.

2.	**Local File Creation**: 
    - Please refrain from creating a local file unless there is a specific reason to do so. 
    -  When creating a file, consider utilizing the `tempfile` package, which ensures efficient cleanup compared to manual file management.


3.  **Error Handle**:

    -	Handle negative test cases effectively by ensuring the use of valid variables. For instance, if accessing a key like 

        `highCount = vulnerability_CloseToSLAHigh['results'][0]['count(data)']`, perform validation using our internal utility library. An example would be:
                    `from compliancecow.utils import dictutils

                    if dictutils.is_valid_array(vulnerability_CloseToSLAHigh, "results") and dictutils.is_valid_array(vulnerability_CloseToSLAHigh["results"][0], "count(data)'"):

                        highCount = vulnerability_CloseToSLAHigh['results'][0]['count(data)']`


    -	Return errors promptly instead of nesting 'if' conditions. For example we can rewrite the above example into,

            `if not dictutils.is_valid_array(vulnerability_CloseToSLAHigh, "results") or not dictutils.is_valid_array(vulnerability_CloseToSLAHigh["results"][0], "count(data)'"):

                return {"error":"invalid data"}`

    -	When handling `try`, `catch` blocks, aim to handle specific exceptions rather than catching all exceptions. This approach helps identify what exceptions might have been overlooked.
 
    -	Instead of using `print` statements, prioritize returning errors with detailed information. This practice enhances error handling and provides better context for debugging and resolving issues.

    -   Categorize errors into two distinct parts:

        1. <u>**CCOW Handling**</u> - Unhandled exceptions occurring during task execution will be managed by CCOW. These errors will be surfaced within CCOW for further action.

        2. <u>**User Handling**</u> - Errors that are managed by the user are best recorded in an audit file. This allows for the attachment of multiple errors and additional contextual details for thorough analysis and resolution.

5.  **Packages**: 
    - Please ensure to include a `requirements.txt` file if your task file relies on external libraries.

6.  **Use native methods**:

    -   Utilize the internal package for file uploading and downloading.

        1.  <u>*Upload*</u>: `file_url, error = self.upload_file_to_minio(file_content=file_content, file_name=file_name, content_type=content_type)`
        2.  <u>*Download*</u>: `file_bytes, error = self.download_file_from_minio(file_url=file_url)`

    -   Utilize the `validate_attributes` method to validate credentials from the application package.

    -   If you encounter validation logic that is applicable across the entire application, relocate it to the application level.

 
7.	**Compliance Calculation**:

    1. Compliance calculation will be handled by us if the following conditions are met:

        - Your evidence file should include a column titled `ComplianceStatus`.
        
        - The permitted values for this column are `COMPLIANT`, `NON_COMPLIANT`, and `NOT_DETERMINED`. Any other values will be designated as `NOT_DETERMINED`.
        
        - The compliance percentage will be calculated using the formula: `number of compliance rows / total number of rows`.

    2.  If you prefer not to add a new column, you can calculate the result and return it as output.


8.  **Credentials**:

    -   If you are handling credentials, we recommend utilizing environment variables to prevent accidental inclusion in the codebase.



## Python

1.	**pandas**: 

    -   Prior to accessing the dataframe, verify its emptiness using a check such as `not df.empty`.

    -   Please ensure to verify the availability of columns before accessing them.

    -   For optimal performance when performing operations on columns, please adhere to the following preferred order:

        1. Utilize vectorization techniques.
        2. Employ custom Cython routines.
        3. Utilize the `apply` method, prioritizing:
            - Reducing operations that can be executed in Cython.
            - Iterating within the Python space.
        4. Use `itertuples`.
        5. Consider `iterrows`.
        6. As a last resort, update an empty DataFrame, such as using `loc` one row at a time.


2. **Naming Conventions**:
   - Use descriptive names for variables, functions, classes, and modules.
   - Use `lowercase` for variable names, `UPPERCASE` for constants, `CapitalizedWords` for class names, and `snake_case` for function names and method names.
   - Avoid single-character names except for loop variables.

3. **Comments**:
   - Write clear and concise comments to explain your code where necessary.
   - Use docstrings to document modules, classes, and functions.
   - Avoid comments that merely restate the code. Focus on explaining why the code is written the way it is, not what it does.

4. **Imports**:
   - Import modules at the top of your script or module.
   - Organize imports in the following order: standard library imports, related third-party imports, local application/library-specific imports.
   - Use absolute imports (`import module`) rather than relative imports (`from . import module`).

9. **Use Built-in Functions and Libraries**:
   - Whenever possible, use built-in functions and libraries to perform common tasks rather than reinventing the wheel.

10. **Documentation**:
    - Document your code using inline comments, docstrings, and README files.
    - Provide clear instructions on how to use your code and any dependencies it may have.

Following these guidelines will help you write clean, maintainable, and understandable Python code.

