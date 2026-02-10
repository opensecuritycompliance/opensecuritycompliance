The purpose of this task is to automate API requests. It allows users to make API calls programmatically, extracting necessary input parameters like methods, request bodies, headers, and other required information from an input file. The task processes these inputs, executes the API requests, and captures the responses, outputting them in a structured format.


### **InputsAndOutputsStructure:** 
- Inputs :
    - **InputFile**                        : [OPTIONAL] The file is iterated over for each data entry, the API sends a request for each entry, and all responses are collected and returned.
    - **InputFileValidationConfig**        : [OPTIONAL] This field checks for required fields in the input file, removes duplicates based on selected fields, and returns an error if any required fields are missing.
    - **RequestConfigFile**                : [MANDATORY] This file contains all the information about the api request.
    - **ResponseConfigFile**               : [OPTIONAL] This file is required only if we need to process or manipulate the HTTP response output.
    - **ProceedIfLogExists**               : [OPTIONAL] If the previous task returns a log file and passes it to the current task, this field determines whether the current task should proceed and return the log file at the end of execution, or stop immediately and return the log file. The default value is true.
    - **ProceedIfErrorExists**             : [OPTIONAL] If the current task returns an error, this field determines whether to return the log file and continue to the next task, or to stop the entire rule execution. The default value is true.
    - **LogConfigFile**                     : [OPTIONAL] This file defines all exception messages and error-handling details for the current task. It is a TOML file containing predefined fields with placeholder values, which will be dynamically replaced at runtime based on the task’s context.
    - **LogFile**                          : [OPTIONAL] Map the LogFile from the previous task, to handle errors
- Outputs :
    - **OutputFile**                       : This file contains the response details.
    - **LogFile**                          : If any errors arise in the task then this will catch all the errors


### **InputsSection:**
1. InputFile **(OPTIONAL)**
    - InputFile data is iterated for each data api will send request and all the response are collected and returned in json formate.
    - For example in the below 'InputFile' we have 3 resourceGroups names, my aim is to get the resourceGroups details of mentioned in the 'InputFile', so 3 api call will be send in this task.
    we can access the InputFile data using <<inputfile.FIELD_NAME>>, Lets assumes your are going to get the details of below given 3 'resourceGroups' data in url you simply mention <<inputfile.name>>
    
    URL = "<<application.AppURL>>/subscriptions/<<application.SubscriptionID>>/resourceGroups/<<inputfile.name>>?api-version=2021-04-01"

    Using this api will get all the three 'resourceGroups' details.

    <!-- BELOW IS THE 'InputFile' JSON WITH SAMPLE DATA -->
    ```json
    [
        {
            "id": "/subscriptions/4dc29444-e147-440d-955e-96cbcd2bdfae/resourceGroups/cloud-shell-storage",
            "name": "cloud-shell-storage",
            "type": "Microsoft.Resources/resourceGroups"
        },
        {
            "id": "/subscriptions/4dc29444-e147-440d-955e-96cbcd2bdfae/resourceGroups/cloud-shell-container",
            "name": "cloud-shell-container",
            "type": "Microsoft.Resources/resourceGroups"
        },
        {
            "id": "/subscriptions/4dc29444-e147-440d-955e-96cbcd2bdfae/resourceGroups/Testing-aws-bucket",
            "name": "Testing-aws-bucket",
            "type": "Microsoft.Resources/resourceGroups"
        }
    ]
    ```

2. InputFileValidationConfig **(OPTIONAL)**
    - This field is used to check if required fields are present in the input file.
    - You can also use it to remove duplicate records based on selected fields.
    - If any required fields are missing, an error will be returned.

    <!-- BELOW IS THE 'InputFileValidationConfig' JSON WITH SAMPLE DATA -->
    ```json
    [
        {
            "FileName": "InputFile",
            "RequiredFields": ["Field1", "Field2"],
            "RemoveDuplicates": true
        }
    ]
    ```  

3. RequestConfigFile **(MANDATORY)**
    - 'RequestConfigFile' file contains all the information about the api request, Each field are explained in the below sample toml file 

    <!-- BELOW IS THE 'RequestConfigFile' TOML FILE WITH SAMPLE DATA -->
    ```toml
    # The Variables section allows you to define constants that can be used dynamically in the request below.
    # - You can reference these variables anywhere in the request using the <<variable_name>> syntax.
    # - Ensure all values are strings. For non-string values (like objects), convert them to JSON-formatted strings.
    # Example:
    #   - Method = "GET" can be referenced in the [Request] section as <<Method>>.
    #   - Params = "sample data" can be used in the query string or body as <<Params>>.
    [Variable]
    Method = "GET"
    CredentialType = "OAuth"
    Params = "Params sample data"
    Raw = "Raw sample data"

    # The Request section contains the general configuration for making the API request.
    [Request]

    # URL Field --> MANDATORY
    # - Specify the complete API URL or build it dynamically using application variables.
    # - You can access application-level fields using the syntax <<application.FieldName>>.
    # Example:
    # - Using Azure APIs: Combine AppURL and SubscriptionID:
    #   "<<application.AppURL>>/subscriptions/<<application.SubscriptionID>>/resourcegroups?api-version=2021-04-01"
    # - Using AWS APIs: 
    #   "<<application.AppURL>>/ListRoles" translates to "https://iam.amazonaws.com/ListRoles".
    URL = "https://iam.amazonaws.com/"

    # HTTP Method --> MANDATORY
    # - Specify the HTTP method to use for the request.
    # - Supported values: 
    #   GET, POST, PUT, DELETE, PATCH.
    Method = "<<Method>>"

    # Content Type --> Required when the request has 'Data' (Refer 'Request.Data' field for more information)
    # - Specify the Content-Type header to define the format of the request body.
    # - Supported values: 
    #   multipart/form-data, application/x-www-form-urlencoded, application/json, application/octet-stream.
    ContentType = "multipart/form-data"

    # Follow Redirects --> OPTIONAL - default is 'false'
    # - Set to true if HTTP redirects should be followed automatically.
    # - Set to false if redirects should not be followed.
    Redirect = true

    # Credential Type --> MANDATORY
    # Select the credential type for the request. Options include:
    # AWSSignature, BasicAuthentication, BearerToken, APIKey, OAuth, JWTBearer, CustomType, NoAuth

    # === AUTO-GENERATED HEADERS (No need to specify Authorization manually) ===

    # -> AWSSignature:
    #    - Automatically infers AWS service and region from URL
    #    - Adds Authorization, x-amz-date, and x-amz-content-sha256 headers
    #    - Do NOT specify Authorization header manually
    #    - Does NOT require 'ValidationCurl'

    # -> BasicAuthentication:
    #    - Automatically adds "Authorization: Basic <base64(username:password)>"
    #    - Do NOT specify Authorization header manually
    #    - Requires 'ValidationCurl'

    # -> BearerToken:
    #    - Automatically adds "Authorization: Bearer <token>"
    #    - Do NOT specify Authorization header manually
    #    - Requires 'ValidationCurl'

    # -> APIKey:
    #    - Automatically adds "Authorization: <api_key>"
    #    - Do NOT specify Authorization header manually
    #    - Requires 'ValidationCurl'

    # -> NoAuth:
    #    - No authentication is applied. No headers required
    #    - Does NOT require 'ValidationCurl'
    #    - This type is used when no authentication mechanism is needed

    # === MANUAL AUTHORIZATION HEADER REQUIRED (Specify in [Request.Headers]) ===

    # -> OAuth:
    #    - Must specify Authorization header using <<validationCURLresponse.*>>
    #    - Requires 'ValidationCurl'
    #    - Example:
    #      Authorization = "<<validationCURLresponse.token_type>> <<validationCURLresponse.access_token>>"

    # -> CustomType:
    #    - Must specify Authorization header using <<validationCURLresponse.*>>
    #    - Requires 'ValidationCurl'
    #    - Using this type you can have user-defined 'key' as well as 'value'
    #    - For example, Azure API requires 'ClientID', 'ClientSecret', 'TenantID', 'SubscriptionID'
    #    - Under 'Application.CustomType' you can mention all the required credentials
    #    - Access them in 'ValidationCurl' (refer '[Request.Headers]' for more information)
    #    - Example:
    #      Authorization = "<<validationCURLresponse.tokenType>> <<validationCURLresponse.authToken>>"

    # -> JWTBearer:
    #    - Requires Authorization header
    #    - Requires 'ValidationCurl'
    #    - Option 1 (auto): Authorization = "Bearer <<JWTBearer>>"
    #      (for JWT generated using Algorithm, PrivateKey, Payload)
    #    - Option 2 (manual): Authorization = "<<validationCURLresponse.token>>"
    #      (if using validationCURL)
    #    
    #    For the Payload field, you can specify the following placeholders in the syntax: <<FUNCTION_NAME>>
    #    
    #    SUPPORTED FUNCTIONS:
    #    - CURRENT_TIME: Replaces with the current time in Unix format
    #                    You can also add/subtract integer values: <<CURRENT_TIME + 3600>> or <<CURRENT_TIME - 1800>>
    #    - CURRENT_DATE: Replaces with the current date in ISO format
    #    
    #    EXAMPLE Payload:
    #    {
    #      "iss": "test@some-project.iam.gserviceaccount.com",
    #      "sub": "test@some-project.iam.gserviceaccount.com",
    #      "aud": "https://oauth2.googleapis.com/token",
    #      "scope": "https://www.googleapis.com/auth/logging.read",
    #      "iat": <<CURRENT_TIME>>,
    #      "exp": <<CURRENT_TIME + 3600>>
    #    }

    CredentialType = "<<CredentialType>>"

    # TimeOut --> OPTIONAL
    # - Specify the timeout for the request in seconds.
    TimeOut = 30  

    # Verify --> MANDATORY
    # The verify parameter in the requests is used to specify whether SSL certificates should be verified when making an HTTPS request. 
    # Here's how it works:
    # verify=True: Validates SSL certificates against trusted CA bundles (default). Ensures secure communication.
    # verify=False: Disables SSL certificate validation. Not recommended for production due to security risks.
    Verify = true

    # Number of threads to use for parallel API requests
    # - Increase for faster parallel processing
    # - Decrease to reduce system load (especially in limited environments like Docker)
    # - If MaxWorkers is set to 1, requests are made sequentially
    # - If set too high (e.g., >20), it will be capped at 20 to protect system performance
    MaxWorkers = 5

        [Request.Retries.RetryOnCondition]
        # Configure the retry logic based on specific conditions.

        ConditionField = "<<response.status_code>>"
        # The response attribute used to determine whether a retry should be attempted.
        # This can be any response property, such as status_code, headers, body, cookies, or url.

        ConditionValue = "503|504|429"
        # Specifies the values that trigger a retry, separated by a pipe (|).
        # Supports multiple values (e.g., "503|504|429") or a single value (e.g., "200").

        TimeInterval = 2
        # The wait time (in seconds) between consecutive retry attempts.

        MaxRetries = 3 
        # The maximum number of retry attempts before stopping further retries.


    # Request Headers Section: You can add custom headers here as needed.
    #
    # The 'Authorization' field is NOT required for the following CredentialTypes:
    #   [AWSSignature, BasicAuthentication, BearerToken, APIKey]
    # Because it will be generated automatically based on 'CredentialType'.
    #
    # For the following CredentialTypes, you MUST define the 'Authorization' header manually:
    #   [CustomType, OAuth, JWTBearer]
    #
    # === CustomType & OAuth ===
    # These CredentialTypes require a validation CURL (ValidationCURL) in the Application configuration
    # to generate the Authorization token dynamically.
    # You can specify that CURL in the application, and then reference its response here.
    #
    # EXAMPLE (Azure OAuth):
    # --------------------------------------------------
    # 1. Application -> ValidationCURL
    #    For Azure APIs, you can generate a Bearer token using:
    #
    #    curl --location 'https://login.microsoftonline.com/<<CustomType.TenantID>>/oauth2/token' \
    #         --header 'Content-Type: application/x-www-form-urlencoded' \
    #         --data-urlencode 'grant_type=client_credentials' \
    #         --data-urlencode 'client_id=<<CustomType.ClientID>>' \
    #         --data-urlencode 'client_secret=<<CustomType.ClientSecret>>' \
    #         --data-urlencode 'resource=https://servicebus.azure.net'
    #
    # 2. RequestConfigFile -> [Request.Headers]
    #    Once the CURL is validated, you can access its response dynamically:
    #
    #    Authorization = "<<validationCURLresponse.token_type>> <<validationCURLresponse.access_token>>"
    #
    # === JWTBearer ===
    # - Option 1 (auto): Authorization = "Bearer <<JWTBearer>>"
    #                    (uses Algorithm, PrivateKey, Payload defined in Application)
    # - Option 2 (manual): Authorization = "<<validationCURLresponse.token>>"
    #                      (if using validationCURL)
    #
    # === NoAuth ===
    # - No Authorization header required.
    #
    [Request.Headers]
        # === For OAuth/CustomType: Uncomment and use one of these ===
        # Authorization = "<<validationCURLresponse.token_type>> <<validationCURLresponse.access_token>>"
        # Authorization = "<<validationCURLresponse.tokenType>> <<validationCURLresponse.authToken>>"
        # NOTE : Add "<<validationCURLresponse>>" to include the full validation cURL response.
        #        This means that if the validation cURL returns an Auth token or a Bearer token in plain/text,
        #        the entire response will be directly used as the value of the `Authorization` header.

        
        # === For JWTBearer (auto-generated): Uncomment if needed ===
        # Authorization = "Bearer <<JWTBearer>>"
        
        # === For JWTBearer (manual with validationCURL): Uncomment if needed ===
        # Authorization = "<<validationCURLresponse.token>>"
        
        # Specify additional HTTP headers as key-value pair in the format: key = value.
        # Example:
        # Content-Type = "application/json"
        # Connection = "keep-alive"  

    # Query Parameters:
    # - Define query parameters for GET requests or additional parameters for other request types.
    # - Specify parameters as key-value pair in the format: key = value.
    # - You can use dynamic variables such as <<fromdate>> and <<todate>>.
    
    # When using certain credential types (e.g., AWS signature), the order of query parameters may 
    # impact request signing. Before aligning the query parameters, refer to the respective API’s 
    # documentation to ensure correct formatting and avoid potential ordering issues.

    [Request.Params]
        Params = '{"Arn": "<<Params>>"}'

    # Request Data Section:
    # - Specify the request body based on the ContentType.
    # - Define one of the following sections depending on the request format.
    [Request.Data]
        # Form-Data Body:
        # - Used with ContentType = "multipart/form-data".
        # - Define form fields as key-value pairs.
        # - For file uploads, specify the file path or MinIO storage path.
        [Request.Data.FormData]
        field1 = "Value1"
        field2 = "Value2"

        # URL-Encoded Body:
        # - Used with ContentType = "application/x-www-form-urlencoded".
        # - Define fields to be URL-encoded.
        [Request.Data.URLEncoded]
        field1 = "Value1"
        field2 = "Value2"

        # Raw Body:
        # - Used with ContentType = "application/json", "text/html", "text/plain", or "application/xml".
        # - Define raw data as JSON or plain text.
        [Request.Data.Raw]
        Value = '{"key": "<<Raw>>", "field1": "Value1"}'

        # Binary Body:
        # - Used with ContentType = "application/octet-stream".
        # - Define binary data, such as base64-encoded files.
        [Request.Data.Binary]
        Value = "QmluYXJ5IERhdGE="  # Base64-encoded binary data.
    ```

    ******** Additional Information:  ********
        - You can add any number of key-value pairs in the format key = value for the following sections:
            - Headers: Define additional HTTP headers required for the request.
            - Params: Specify query parameters or additional request parameters.
            - Data: Populate request body fields based on the selected ContentType.
        - You can access the 'FromDate' and 'ToDate' using '<<fromdate>>' and '<<todate>>'
        - You can access dynamic variables from the input file or application configuration using <<inputfile.FieldName>> or <<application.FieldName>>.
        - Example: <<application.SubscriptionID>> can be used to include a subscription ID in the request.

4. ResponseConfigFile **(OPTIONAL)**
    'Response' is a configuration object used to specify how to process HTTP responses based on defined conditions. 'Response' is optional, meaning you can skip passing it as input to the task or leave it as an empty file if necessary.The ResponseConfigFile is required only if you need to manipulate the response output.

    Currently, we support the following functionalities:

    - Appending Column Fields
    - Pagination

    These features are only supported for the content types:

    - application/json
    - application/ld+json

    <!-- BELOW IS THE 'ResponseConfigFile' TOML FILE WITH SAMPLE DATA -->
    ```toml
    # 'Response' is a configuration object used to specify how to process HTTP responses based on defined conditions.
    # 'Response' is optional. You can skip passing it as input to the task, or leave it as an empty file if necessary.

    [Response]

    [Response.Filter]
        JQExpression = ""  
        # JQExpression to process the response body.
        # Example: .[].fields.statuscategorychangedate

        OutputMethod = ""
        # OutputMethod specifies how the output from the JQ filter should be handled.
        # Valid values might include "ALL", "FIRST"(Default).

        # Note:
        # - The JQExpression is optional and only has an effect if specified.
        # - When using the "AppendColumn Fields" feature along with a JQ filter,
        #   the append operation is applied to the filtered response instead of the original unfiltered response.


    # Each entry in the 'RuleSet' contains conditions to evaluate and defines the actions to perform when those conditions are met.
    # Supported action types are 'AppendColumn' and 'Pagination'.
    [Response.RuleSet]

    # Condition for the 'AppendColumn' action
    [Response.RuleSet.AppendColumnCondition]
    # The 'ConditionField' is used to determine when to apply the 'AppendColumn' action.
    # For example, if the response status code is 200, then proceed with appending columns to the output.
    # 'ConditionField' is not mandatory; you can leave it as an empty string.
    # In that case, it won't check any condition and will directly append the columns to the output.
    ConditionField = "<<response.status_code>>"
    ConditionValue = "200"

    [Response.RuleSet.AppendColumn]
    # If you want to include all columns from the input file in the output, set 'IncludeAllInputFields' to true.
    # This eliminates the need to specify each column individually in 'AppendColumn'.
    # If you want to add only specific fields from the input file, use the 'AppendColumn' section instead.
    IncludeAllInputFields = true
    
    [Response.RuleSet.AppendColumn.Fields]
    # You can add custom fields to the output.
    # Example
    # Status = "AccountDisabled" 

    # You can add fields from the input file to the output using the "inputfile." prefix inside "<<>>".
    # 'inputfile' refers to the input file for the task, "InputFile.json".
    # Example
    # Arn = "<<inputfile.Arn>>"  

    # To access a specific value from the array, use the index (e.g., "owners[0]" for the first element). 
    # To access the entire array, use [] in place of the index (e.g., "<<inputfile.owners[].name>>").
    # Example
    # Owners = "<<inputfile.Owners[].name>>"  

    # You can add fields from the request config to the output using the "request." prefix inside "<<>>".
    # 'request' refers to the input file for the task, "RequestConfigFile.toml".
    # Example
    # URL = "<<request.URL>>"      

    # You can add fields from the raw API response using the "response." prefix inside "<<>>".
    # 'response' contains the following fields:
    # { 
    #     "url": "request URL",
    #     "body": "response body in JSON format",
    #     "status_code": "response status code",
    #     "headers": "response headers",
    #     "cookies": "response cookies",
    #     "links": [ // Content from the Link header in the response, if it exists
    #         "link_name": {
    #             "rel": "link_name",
    #             "url": "link url"
    #         }
    #     ]
    # }
    # Example
    # StatusCode = "<<response.status_code>>"  

    # You can reference fields from the JSON response body using the "response.body." prefix within "<<>>". 
    # To access a field in a JSON object or array, simply use "<<response.body.ID>>". 
    # If the response body is an array (e.g., [{}, {}]), this query will apply to all objects in the array.
    # Example
    # ID = "<<response.body.ID>>"       

    # Condition for the 'Pagination' action
    [Response.RuleSet.PaginationCondition]
    # Specify conditions for triggering pagination actions
    # MAKE SURE : Pagination will stop only when the specified codition gets matched.
    # Example:
    #   ConditionField = "<<response.body.entries>>"
    #   ConditionValue = ""
    ConditionField = ""
    ConditionValue = ""

    [Response.RuleSet.Pagination]
        # ------------------------------------------------------------------------------
        # MAKE SURE YOU ACCESS ALL THE RESPONSE DATA USING <<response.body.key>> ,  <<response.headers.key>>, 
        # <<response.headers.key>>,  <<response.cookies.key>>
        # ------------------------------------------------------------------------------
        # In the below parameters, you can access all the field mentioned in 'Response.RuleSet.AppendColumn.Fields'.
        # In addition to that, you can also access <<fromdate>> and <<todate>>.
        # All 'Pagination' fields should be  specifed as key-value pair in the format: key = value.
        URL = ""  # Specify the API endpoint.
        
        [Response.RuleSet.Pagination.Header]
        # Example:
        # pageToken = "<<response.body.nextPageToken>>"

        # For Query Params
        [Response.RuleSet.Pagination.Params]
        # Example:
        # pageToken = "<<response.body.nextPageToken>>"

        # For URLEncoded data
        [Response.RuleSet.Pagination.Data.URLEncoded]
        # Example:
        # pageToken = "<<response.body.nextPageToken>>"

        # For FormData 
        [Response.RuleSet.Pagination.Data.FormData]
        # Example:
        # pageToken = "<<response.body.nextPageToken>>"

        # For Raw data
        [Response.RuleSet.Pagination.Data.Raw]
        # Example:
        # Value = '{"pageToken": "<<response.body.nextPageToken>>"}'

        # For FormData 
        [Response.RuleSet.Pagination.Data.Binary]
        # Example:
        # Value = "QmluYXJ5IERhdGE="

        ```

5. ProceedIfLogExists **(OPTIONAL)**
    - This field is optional, and the default value of ProceedIfLogExists is true.
    - If ProceedIfLogExists is set to true, the task will continue its execution and return the LogFile at the end.
    - If it is set to false and a log file is already present, the task will skip further execution and simply return the existing LogFile.

6. ProceedIfErrorExists **(OPTIONAL)**
    - This field is optional, and the default value of ProceedIfErrorExists is true.
    - If ProceedIfErrorExists is set to true, the task will return the error details as part of the LogFile and continue to the next task.
    - If it is set to false, the error details will be returned, and the entire rule execution will be stopped.

7. LogConfigFile **(OPTIONAL)**
    - This file defines exception messages and error-handling logic for the current task.
    - It is a TOML file containing predefined fields with placeholders that are dynamically replaced at runtime based on the task’s context.
    - If a placeholder in the TOML file cannot be resolved at runtime, an error will be raised.
    - At the task level, a default file named `LogConfig_default.toml` is used if the user does not provide a custom configuration.
    - For example:
    ```toml
    [ExecuteHttpRequest]
    LogFile.download_failed = "Unable to download the log file from MinIO. Please find more details: {Error}"
    ```
    In this example, the {error} placeholder will be replaced with the actual error message at runtime. If the placeholder is invalid or cannot be resolved, the system will raise an error.  

    We can also include the from and to dates in the error message for better clarity using the {fromdate} and {todate} placeholders. 

8. LogFile **(OPTIONAL)**
    - This field is required only when this task is not acting as task1 in the rule.
    - Generally when the previous task has 'LogFile' it will pass that log file to this task and If the 'LogFile' is empty, it will process 'ExecuteHttpRequest' task else will check other required inputs exist if they do not will simply pass this previous task 'LogFile' to 'ExecuteHttpRequest' task 'LogFile'.


### **OutputsSection:**
1. OutputFile
    - This file contains the response details.
2. LogFile
    - If any errors arise in the task then this will catch all the errors


### **NOTE:**

## Libmagic Installation

python-magic is a Python interface for libmagic, which identifies file types by headers. As a wrapper for the libmagic C library, it requires libmagic to be installed separately:

Debian/Ubuntu: 

    sudo apt-get install libmagic1

Windows: 

    pip install python-magic-bin (includes DLLs)

macOS:

    Homebrew: brew install libmagic

    MacPorts: port install file

## Supported Content Types for Output File

The following content types are supported for generating output files, along with their corresponding file extensions:

#### **Binary Formats:**
- `binary/octet-stream`  
- `application/octet-stream`  

#### **Data Formats:**
- `application/csv` (`.csv`)  
- `application/x-yaml` (`.yaml`)  
- `application/yaml` (`.yaml`)  
- `application/x-tar` (`.tar`)  
- `application/tar` (`.tar`)  
- `application/x-gzip` (`.tgz`, `.gz`)  
- `application/gzip` (`.tgz`, `.gz`)  
- `application/zip` (`.zip`)  
- `application/x-zip` (`.zip`)  
- `application/json` (`.json`)  
- `application/ld+json` (`.jsonld`)  
- `application/xml` (`.xml`)  

#### **Text Formats:**
- `text/css` (`.css`)  
- `text/csv` (`.csv`)  
- `text/html` (`.html`)  
- `text/plain` (`.txt`)  
- `text/javascript` (`.js`)  
- `text/xml` (`.xml`)  

Please ensure the response content type matches one of the supported types for correct processing.