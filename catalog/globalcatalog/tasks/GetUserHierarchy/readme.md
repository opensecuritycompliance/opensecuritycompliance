
- **Name**: GetUserHierarchy


- **Purpose**: The purpose of this task is to determine and return the reporting hierarchy of a user based on provided input data. The task uses a CSV file containing manager-user mappings and a JSON file with user-specific input. Depending on the user’s choice, the task outputs either the immediate manager or the full hierarchy of reporting managers for the given user. The result is generated programmatically and returned in a structured format such as JSON, allowing seamless integration with other systems or use in organizational reporting.

- **InputsAndOutputsStructure**:

    - Inputs :
        LogFile : <<MINIO_FILE_PATH>>
        Type : STRING 
        InputFile : <<MINIO_FILE_PATH>> 
        ConfigFile : <<MINIO_FILE_PATH>>
        HierarchyFile : <<MINIO_FILE_PATH>>
        
    - Outputs :
        OutputFile : <<MINIO_FILE_PATH>>
        LogFile :  <<MINIO_FILE_PATH>>


- **InputsSection**:
    
    1. LogFile (Optional)
        - This field is required only when this task is not acting as task1 in the rule.

        - Generally when the previous task has 'LogFile' it will pass that log file to this task and If the 'LogFile' is empty, it will process 'GetUserHierarchy' task else will check other required inputs exist if they do not will simply pass this previous task 'LogFile' to 'GetUserHierarchy' task 'LogFile'.

    2. Type (Mandatory)
        - 'Type' refers to the user's choice of the type of reporting structure to retrieve — either the immediate manager or the full hierarchy of reporting managers for the given users.

        - Accepted Values : 
            Manager → Returns only the immediate manager
            Hierarchy → Returns the full reporting chain from the user up to the top-level manager

    3. InputFile (Mandatory)      
        - 'InputFile' is a JSON file that contains a list of user data. Each entry is processed to determine its reporting structure, based on the selected Type.

        - The script iterates over each record in the input file, uses the user name field specified in the configuration, and returns the reporting information in the same format.

        <!-- BELOW IS THE 'ResponseConfigFile' TOML FILE WITH SAMPLE DATA -->
        ```JSON
        [
            {
                "UserName": "Alice",
                "Role": "Developer",
                "Department": "Engineering",
                "Email": "alice@example.com",
                "Location": "New York",
                "JoiningDate": "2022-06-15",
                "Skills": ["Python", "Django", "REST APIs"]
            },
            {
                "UserName": "Bob",
                "Role": "Senior Developer",
                "Department": "Engineering",
                "Email": "bob@example.com",
                "Location": "San Francisco",
                "JoiningDate": "2020-04-10",
                "Skills": ["Java", "Spring Boot", "Microservices"]
            }
        ]
        ```

    4. ConfigFile (Mandatory)
        - 'ConfigFile' is a TOML configuration file required to guide how user and manager details should be extracted and processed.

        - It specifies : 
            The user column in the input and hierarchy files
            The output column for manager or hierarchy data

        <!-- BELOW IS THE 'ResponseConfigFile' TOML FILE WITH SAMPLE DATA -->
        ```toml
        [InputFile]
        UserColumn = "UserName"
        NewColumn = "Hierarchy" 

        [HierarchyFile]
        UserColumn = "User"
        ManagerColumn = "Manager" 
        ```

    5. HierarchyFile (Mandatory)
        - 'HierarchyFile' is a CSV file that defines the reporting structure between users and their managers.

        - Each row maps a user to their direct manager.

        <!-- BELOW IS THE 'ResponseConfigFile' TOML FILE WITH SAMPLE DATA -->
        ```csv
        User,Manager
        Alice,David
        Bob,David
        Charlie,David
        Eve,David
        Frank,David
        David,Grace
        Grace,Henry
        ```

- **OutputsSection**:

    1. OutputFile 
        - 'OutputFile' is the result file where a new column is added to each record in the input file.

        - The column name is taken from the ConfigFile > NewColumn, and its value depends on the chosen type : 
            For Manager, the column contains the immediate manager's name.
            For Hierarchy, the column contains an array of all reporting managers (from direct to top-level).

    2. LogFile
        - If any errors arise in the task then this will catch all the errors

