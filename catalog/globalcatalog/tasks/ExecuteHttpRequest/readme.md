
- **Name**: ExecuteHttpRequest


- **Purpose**: The purpose of this task is to automate API requests. It allows users to make API calls programmatically, extracting necessary input parameters like methods, request bodies, headers, and other required information from an input file. The task processes these inputs, executes the API requests, and captures the responses, outputting them in a structured format, such as a JSON file.


- **InputsAndOutputsStructure**:
    - Inputs :
        LogFile :  <<MINIO_FILE_PATH>>
        RequestConfigFile :  <<MINIO_FILE_PATH>>
        ResponseConfigFile:  <<MINIO_FILE_PATH>>
        InputFile:  <<MINIO_FILE_PATH>>
    - Outputs :
        OutputFile : <<MINIO_FILE_PATH>>
        LogFile :  <<MINIO_FILE_PATH>>


- **InputsSection**:
    1. LogFile (Optional)
        - This field is required only when this task is not acting as task1 in the rule.
        - Generally when the previous task has 'LogFile' it will pass that log file to this task and If the 'LogFile' is empty, it will process 'ExecuteHttpRequest' task else will check other required inputs exist if they do not will simply pass this previous task 'LogFile' to 'ExecuteHttpRequest' task 'LogFile'.

    2. RequestConfigFile (Mandatory)

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
        # AWSSignature, BasicAuthentication, BearerToken, OAuth, CustomType, NoAuth
        # -> AWSSignature: Doesn't required 'ValidationCurl' it will generate the auth headers internally.
        # -> BasicAuthentication: Required 'ValidationCurl'
        # -> BearerToken: Required 'ValidationCurl'
        # -> OAuth: Required 'ValidationCurl'
        # -> JWTBearer: Required 'ValidationCurl'
        # -> NoAuth: Doesn't require 'ValidationCurl'. This type is used when no authentication mechanism is needed. Requests will not include any authentication headers or tokens by default.
        # -> CustomType: Required 'ValidationCurl'. Using this type you can have userdefined 'key' as well as 'value' . for example azure api requires 'ClientID' , 'ClientSecret' ,TenantID' , 'SubscriptionID' . under 'Application.CustomType' you can mention all the required creddentials. And access them in 'ValidationCurl' (refer '[Request.Headers]' for more information)
        CredentialType = "<<CredentialType>>"

        # For JWTBearer Credential:
        # -> For the Payload field, you can specify the following placeholders in the following syntax: <<FUNCTION_NAME>>
        # -> SUPPORTED FUNCTIONS:
        # -> - CURRENT_TIME - Replaces with the current time in Unix format. 
        #                   - You can also add/subtract integer values from the resulting value, by mentioning without the square brackets: <<CURRENT_TIME [ + or - ] [seconds-to-add]>>
        # -> - CURRENT_DATE - Replaces with the current date in ISO format
        # -> EXAMPLE: {"iss": "test@some-project.iam.gserviceaccount.com", "sub": "test@some-project.iam.gserviceaccount.com", "aud": "https://oauth2.googleapis.com/token", "scope": "https://www.googleapis.com/auth/logging.read", "iat": <<CURRENT_TIME>>, "exp": <<CURRENT_TIME + 3600>>}

        # TimeOut --> OPTIONAL
        # - Specify the timeout for the request in seconds.
        TimeOut = 30  

        # Verify --> MANDATORY
        # The verify parameter in the requests is used to specify whether SSL certificates should be verified when making an HTTPS request. 
        # Here's how it works:
        # verify=True: Validates SSL certificates against trusted CA bundles (default). Ensures secure communication.
        # verify=False: Disables SSL certificate validation. Not recommended for production due to security risks.
        Verify = true

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
        # The 'Authorization' field is not required for [AWSSignature, BasicAuthentication, BearerToken] as it will be generated internally based on 'CredentialType'.
        # For the following 'CredentialType' [CustomType, OAuth] header is required in 'RequestConfigFile'
        # [CustomType, OAuth] credential types requires a validation curl to generate auth headers, 
        # you can simply give that API CURL in application under 'ValidationCURL'. And access that CURL response.
        # FOR INSTANCE : --------------------------------------------------

            # 1. Application -> ValidationCURL
                # For Azure API you need to generate a 'Bearer' token using below CURL. 

                # curl --location 'https://login.microsoftonline.com/<<CustomType.TenantID>>/oauth2/token' \
                #     --header 'Content-Type: application/x-www-form-urlencoded' \
                #     --data-urlencode 'grant_type=client_credentials' \
                #     --data-urlencode 'client_id=<<CustomType.ClientID>>'\
                #     --data-urlencode 'client_secret=<<CustomType.ClientSecret>>' \
                #     --data-urlencode 'resource=https://servicebus.azure.net'

            # 2. RequestConfigFile -> Headers
                # you can access this CURL response body 
                # Headers =  '{"Authorization": "<<validationCURLresponse.token_type>> <<validationCURLresponse.access_token>>"}'

        # -------------------------------------------------------------------
        # - Specify additional HTTP headers as key-value pair in the format: key = value.
        # For example:
        #     Content-Type = "application/json"
        #     Connection = "keep-alive"
        [Request.Headers]
            Headers = '{"Authorization": "<<validationCURLresponse.token_type>> <<validationCURLresponse.access_token>>"}'  

        # Query Parameters:
        # - Define query parameters for GET requests or additional parameters for other request types.
        # - Specify parameters as key-value pair in the format: key = value.
        # - You can use dynamic variables such as <<fromdate>> and <<todate>>.
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

    3. ResponseConfigFile (Optional)

        'Response' is a configuration object used to specify how to process HTTP responses based on defined conditions. 'Response' is optional, meaning you can skip passing it as input to the task or leave it as an empty file if necessary.The ResponseConfigFile is required only if you need to manipulate the response output.

        Currently, we support the following functionalities:

        - Appending Column Fields
        - Pagination

        These features are only supported for the content types:

        - application/json
        - application/ld+json

        <!-- BELOW IS THE 'ResponseConfigFile' TOML FILE WITH SAMPLE DATA -->
        ```toml
        [Response]

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
            Status = "AccountDisabled" 

            # You can add fields from the input file to the output using the "inputfile." prefix inside "<<>>".
            # 'inputfile' refers to the input file for the task, "InputFile.json".
            Arn = "<<inputfile.Arn>>"  

            # To access a specific value from the array, use the index (e.g., "owners[0]" for the first element). 
            # To access the entire array, use [x] in place of the index (e.g., "<<inputfile.owners[x].name>>").
            Owners = "<<inputfile.Owners[x].name>>"  

            # You can add fields from the request config to the output using the "request." prefix inside "<<>>".
            # 'request' refers to the input file for the task, "RequestConfigFile.toml".
            URL = "<<request.URL>>"      

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
            StatusCode = "<<response.status_code>>"  

            # You can reference fields from the JSON response body using the "response.body." prefix within "<<>>". 
            # To access a field in a JSON object or array, simply use "<<response.body.ID>>". 
            # If the response body is an array (e.g., [{}, {}]), this query will apply to all objects in the array.
            ID = "<<response.body.ID>>"       

            # Condition for the 'Pagination' action
            [Response.RuleSet.PaginationCondition]
            # Specify conditions for triggering pagination actions
            # MAKE SURE : Pagination will stop only when the specified codition gets matched.
            ConditionField = "<<response.body.nextPageToken>>"
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
                pageToken = "<<response.body.nextPageToken>>"

                # For Query Params
                [Response.RuleSet.Pagination.Params]
                pageToken = "<<response.body.nextPageToken>>"

                # For URLEncoded data
                [Response.RuleSet.Pagination.Data.URLEncoded]
                pageToken = "<<response.body.nextPageToken>>"

                # For FormData 
                [Response.RuleSet.Pagination.Data.FormData]
                pageToken = "<<response.body.nextPageToken>>"

                # For Raw data
                [Response.RuleSet.Pagination.Data.Raw]
                Value = '{"pageToken": "<<response.body.nextPageToken>>"}'

                # For FormData 
                [Response.RuleSet.Pagination.Data.Binary]
                Value = "QmluYXJ5IERhdGE="

        ```

    4. InputFile (Mandatory)
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


- **OutputsSection**:
    1. OutputFile
        - This file contains the response details.
    2. LogFile
        - If any errors arise in the task then this will catch all the errors


- **NOTE:**

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