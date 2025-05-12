# **TransformData - README**

**TransformData**  allows you to perform a variety of column transformations on your input data files. You can add new columns, update existing columns, delete columns, and reorder columns. Below is a detailed guide on how to use these features effectively.

---

## **InputsAndOutputsStructure**

### **Inputs:**

- InputFile1          :  The input file to be transformed. [MANDATORY]

- TransformConfigFile :  The toml file containing the transformation configuration. [MANDATORY]

- InputFile2          : This input file is an optional file used to add additional context to the data in **InputFile1**s. This file typically contains data that helps establish relationships or enrich the data from **InputFile1**. [OPTIONAL]

- LogFile             :  This field is required only when this task is not acting as Task1 in the rule. Generally, when the previous task has a 'LogFile,' we will map that logfile to this input in the NoCode UI. If the 'LogFile' is empty, the 'TransformData' task will be processed. Otherwise, it will simply pass the previous task's 'LogFile' to the 'TransformData' task's 'LogFile. [OPTIONAL]

### **Outputs:**

- OutputFile :  The output file that contains the transformed data.

- LogFile    :  The log file that contains details about any errors or issues during the transformation process, or the log from the previous task.

---

## **InputsSection**

### **InputFile1:**

  File that requires transformations. It typically contains the raw data to be processed and transformed according to the rules specified in the TransformConfigFile. The file format for **InputFile1** is  JSON.
  The data in **InputFile1** can include multiple columns and values, which can be modified, added, deleted, or reordered based on the transformations defined in the TransformConfigFile. 

  **Example:**
  ```json
  [
    {
      "UserName": "JohnDanie",
      "Department": "Engineering",
      "Users": ["JohnDanie", "JaneDoe"],
      "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}]
    },
    {
      "UserName": "JosephAntony",
      "Department": "Marketing",
      "Users": ["JosephAntony", "JackSmith"],
      "requested_reviewers": [{"login": "Reviewer3"}, {"login": "Reviewer4"}]
    }
  ]
  ```

### **TransformConfigFile**

 A **TransformConfigFile** containing transformation configuration typically defines operations such as **AddColumn**, **UpdateColumn**, **DeleteColumn**, **ReorderColumn**, and **RemoveDuplicates** for transforming data. Below is a detailed explanation of each type of operation:

 **Important Note:**
   Be sure to define the path correctly using the format `<<file_name.path>>`. For example, if referencing a column in `InputFile1`, use `<<inputfile1.column_name>>`.

#### 1. **Add Column**

The `AddColumn` operation allows you to add new columns to your data (`InputFile1`) in different methods. 

##### **Method 1 - Adding a Column with the Desired Value, Existing Column, or Replacing Placeholders**

**Syntax:**
```toml
[AddColumn]
"NewColumn" = "value"
```

**Syntax explanation:**
- **NewColumn**  : The name of the new column.
- **value**      : The possible ways to give value in the structure below:

      - Fixed value                          : "System" = "aws"
      - Value from InputFile1                : "SystemUserName" = "<<inputfile1.UserName>>"
      - Replace placeholders from InputFile1 : "ResourceURL" = https://portal.azure.com/users/<<inputfile1.UserID>>

**Example:**

**InputFile1:**
```json
[
  {
    "UserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering",
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}]
  },
  {
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [{"login": "Reviewer3"}, {"login": "Reviewer4"}]
  }
]
```

**TransformConfigFile:**
```toml
[AddColumn]
"System" = "aws"
"SystemUserName" = "<<inputfile1.UserName>>"
"ResourceURL" = "https://portal.azure.com/users/<<inputfile1.UserID>>>"
```

**OutputFile:**
```json
[
  {
    "System": "aws",
    "SystemUserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering",
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}],
    "ResourceURL" : "https://portal.azure.com/users/43893443"
  },
  {
    "System": "aws",
    "SystemUserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [{"login": "Reviewer3"}, {"login": "Reviewer4"}],
    "ResourceURL" : "https://portal.azure.com/users/43532253"
  }
]
```

---

##### **Method 2 - Adding a Column by Applying a Function to an Existing Column**

**Note:** Supported Functions - `Length`, `CurrentDateTime`

**Syntax:**
```toml
[[AddColumn.ByFunction]]
ColumnName  = ""         
Source      = ""
Function    = ""
```

**Syntax explanation:**
- **ColumnName**  : The name of the new column.
- **Source**      : The path to the existing column (e.g., `<<inputfile1.Users>>`).
- **Function**    : The transformation function to apply (e.g., `Length`).

**Example for function 'Length':**

**InputFile1:**
```json
[
  {
    "UserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering",
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}]
  },
  {
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [{"login": "Reviewer3"}, {"login": "Reviewer4"}]
  }
]
```

**TransformConfigFile:**
```toml
[[AddColumn.ByFunction]]
ColumnName = "TotalUsers"         
Source = "<<inputfile1.Users>>"
Function = "Length"
```

**OutputFile:**
```json
[
  {
    "UserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering",
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}],
    "TotalUsers" : 2
  },
  {
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [{"login": "Reviewer3"}, {"login": "Reviewer4"}],
    "TotalUsers" : 2
  }
]
```

**Example for function 'CurrentDateTime':**

**Note:** Format for `CurrentDateTime` supported is `%Y-%m-%dT%H:%M:%S.%fZ`

**InputFile1:**
```json
[
  {
    "UserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering",
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}]
  },
  {
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [{"login": "Reviewer3"}, {"login": "Reviewer4"}]
  }
]
```

**TransformConfigFile:**
```toml
[[AddColumn.ByFunction]]
ColumnName = "EvaluationTime"         
Source = ""
Function = "CurrentDateTime"
```

**OutputFile:**
```json
[
  {
    "UserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering",
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}],
    "EvaluationTime" : "2024-12-16T09:01:39.586730Z"
  },
  {
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [{"login": "Reviewer3"}, {"login": "Reviewer4"}],
    "EvaluationTime" : "2024-12-16T09:01:39.586730Z"
  }
]
```
---

##### **Method 3 - Adding a Column as an Object**

You can add a new column by constructing an object from multiple fields in an existing record. The values for the new object can be derived from multiple columns, and they will be combined into a single object.

**Syntax:**
```toml
[[AddColumn.AsObject]]
ColumnName = ""                
ObjectValues = ""               
```

**Syntax explanation:**
- **ColumnName**: The name of the new column.
- **ObjectValues**: A comma-separated list of paths to the fields in the existing record that should be included in the new object. Ensure there are no spaces between the paths.

**Example:**

**InputFile1:**
```json
[
  {
    "UserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering",
    "Users": ["JohnDanie", "JaneDoe"],
    "Role": "Manager",
    "Permission": "ReadWrite",
    "Address": "123 Main St",
    "Profile": {
      "Skills": ["Java", "Python"]
    }
  },
  {
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "Users": ["JosephAntony", "JackSmith"],
    "Role": "Developer",
    "Permission": "Read",
    "Address": "456 Elm St",
    "Profile": {
      "Skills": ["JavaScript", "CSS"]
    }
  }
]
```

**TransformConfigFile:**
```toml
[[AddColumn.AsObject]]
ColumnName = "AdditionalInfo"
ObjectValues = "<<inputfile1.UserID>>,<<inputfile1.Role>>,<<inputfile1.Permission>>,<<inputfile1.Address>>,<<inputfile1.Profile.Skills>>"
```

**OutputFile:**
```json
[
  {
    "UserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering",
    "Users": ["JohnDanie", "JaneDoe"],
    "Role": "Manager",
    "Permission": "ReadWrite",
    "Address": "123 Main St",
    "Profile": {
      "Skills": ["Java", "Python"]
    },
    "AdditionalInfo": {
      "UserID": "43893443",
      "Role": "Manager",
      "Permission": "ReadWrite",
      "Address": "123 Main St",
      "Skills": ["Java", "Python"]
    }
  },
  {
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "Users": ["JosephAntony", "JackSmith"],
    "Role": "Developer",
    "Permission": "Read",
    "Address": "456 Elm St",
    "Profile": {
      "Skills": ["JavaScript", "CSS"]
    },
    "AdditionalInfo": {
      "UserID": "43532253",
      "Role": "Developer",
      "Permission": "Read",
      "Address": "456 Elm St",
      "Skills": ["JavaScript", "CSS"]
    }
  }
]
```

---

##### **Method 4 - Adding a Column Using Mapping**

You can create a new column by mapping data from one file to another. For example, mapping user names to managers:

**Syntax:**
```toml
[[AddColumn.ByMap]]
ColumnName = ""         
Source = ""
Target = ""
TargetMapping = ""
```

**Syntax explanation:**
- **ColumnName**: The name of the new column.
- **Source**: The source column in the InputFile1(e.g., `<<inputfile1.UserName>>`).
- **Target**: The target column in the InputFile2 (e.g., `<<inputfile2.Users>>`).
- **TargetMapping**: The target mapping column in the InputFile2 (e.g., `<<inputfile2.Manager>>`).

**Example:**

**InputFile1:**
```json
[
  {
    "UserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering",
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}]
  },
  {
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [{"login": "Reviewer3"}, {"login": "Reviewer4"}]
  }
]
```

**InputFile2:**
```csv
Users,Manager
JohnDanie,PerterRutherFord
JosephAntony,PerterRutherFord
```

**TransformConfigFile:**
```toml
[[AddColumn.ByMap]]
ColumnName = "Manager"         
Source = "<<inputfile1.UserName>>"
Target = "<<inputfile1.Users>>"
TargetMapping = "<<inputfile1.Manager>>"
```

**OutputFile:**
```json
[
  {
    "UserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering",
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}],
    "Manager" : "PerterRutherFord"
  },
  {
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [{"login": "Reviewer3"}, {"login": "Reviewer4"}],
    "Manager" : "PerterRutherFord"
  }
]
```

---


##### **Method 5 - Adding a Column as a List**

You can add a column as a list with values extracted from a source file or provided as a predefined data:

**Syntax:**
```toml
[[AddColumn.AsList]]
ColumnName = ""         
Source = ""
Target = ""

[[AddColumn.AsList]]
ColumnName = ""         
ListData = []
```

**Syntax explanation:**
- **ColumnName**: The name of the new column.
- **Source**: The path to the data in the source file (e.g., `<<inputfile1.requested_reviewers>>`).
- **Target**: The path to a specific field within the list (e.g., `<<Source.login>>`).
- **ListData**: A predefined list of values to populate the new column (e.g., `"data1,data2,data3"`).

**Example:**

**InputFile1:**
```json
[
  {
    "UserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering",
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [
      {
        "login": "Reviewer1",
        "loginid": "1234",
        "loginmail": "Reviewer1@demo.com"
      }, 
      {
        "login": "Reviewer2",
        "loginid": "6789",
        "loginmail": "Reviewer2@demo.com"
      }
    ]
  },
  {
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [
      {
        "login": "Reviewer3",
        "loginid": "3434",
        "loginmail": "Reviewer3@demo.com"
      }, 
      {
        "login": "Reviewer4",
        "loginid": "1290",
        "loginmail": "Reviewer4@demo.com"
      }
    ]
  }
]
```

**TransformConfigFile:**
```toml
[[AddColumn.AsList]]
ColumnName = "PRReviewers"                      # New column name "PRReviewers"
Source = "<<inputfile1.requested_reviewers>>"   # Source column (requested_reviewers). This should be a List.
Target = "<<Source.login>>"                     # Extracting the "login" field from each object in the list.
# As a result, the column 'PRReviewers' will be added as a list that contains the values of all targets from the source list.

[[AddColumn.AsList]]
ColumnName = "DefaultList"                      # New column name "DefaultList"
ListData = "data1,data2,data3"                  # String with comma seperated values
# As a result, the column 'DefaultList' will be added as a list by splitting 'ListData' with a comma delimiter.
```

**OutputFile:**
```json
[
  {
    "UserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering",
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}],
    "PRReviewers" : ["Reviewer1", "Reviewer2"],
    "DefaultList" : ["data1", "data2", "data3"]
  },
  {
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [{"login": "Reviewer3"}, {"login": "Reviewer4"}],
    "PRReviewers" : ["Reviewer3", "Reviewer4"],
    "DefaultList" : ["data1", "data2", "data3"]
  }
]
```

---

##### **Method 6 - Adding a Column by Condition**

**Syntax:**
```toml
[[AddColumn.ByCondition]]
Condition = ""
# Define behavior for when the condition is true
[[AddColumn.ByCondition.True]]
ColumnName1 = ""
ColumnName2 = ""
# Define behavior for when the condition is false
[[AddColumn.ByCondition.False]]
ColumnName = ""
ColumnName2 = ""
```

**Syntax explanation:**

- **Condition**: A condition that needs to be checked. (Nested structure is not supported (eg : <<inputfile1.User.skills.count>>))
As a result, new columns will be added based on whether the condition evaluates to `True` or `False`.

**Supported Conditions:**

- `==` : Equal to
- `!=` : Not equal to
- `>` : Greater than
- `<` : Less than
- `>=` : Greater than or equal to
- `<=` : Less than or equal to
- `and` : Logical AND
- `or` : Logical OR
- `not` : Logical NOT

Additionally, you can use functions and more complex expressions, such as:

  - `<<inputfile1.requested_reviewers_count>> > 1` (e.g., check if the count is greater than 1)
  - `<<inputfile1.Users>> contains 'JohnDanie'` (e.g., check if a specific user exists in the `Users` list)

**Example 1:**

**InputFile1:**

```json
[
  {
    "UserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering",
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [
      {
        "login": "Reviewer1",
        "loginid": "1234",
        "loginmail": "Reviewer1@demo.com"
      },
      {
        "login": "Reviewer2",
        "loginid": "6789",
        "loginmail": "Reviewer2@demo.com"
      }
    ],
    "requested_reviewers_count": 2
  },
  {
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [
      {
        "login": "Reviewer3",
        "loginid": "3434",
        "loginmail": "Reviewer3@demo.com"
      }
    ],
    "requested_reviewers_count": 1
  }
]
```

**TransformConfigFile:**

```toml
# Adding a new column(s) based on condition
[[AddColumn.ByCondition]]
Condition = "<<inputfile1.requested_reviewers_count>> > 1" # Checking if requested_reviewers_count is greater than 1

# Define behavior for when the condition is true
[[AddColumn.ByCondition.True]]
ValidationStatusCode = "REQ_REV_CNT_MET"
ValidationStatusNotes = "Required reviewers count met"
ComplianceStatus = "COMPLIANT"
ComplianceStatusReason = "The record is compliant because the required number of reviewers is present for the user."

# Define behavior for when the condition is false
[[AddColumn.ByCondition.False]]
ValidationStatusCode = "REQ_REV_CNT_NT_MET"
ValidationStatusNotes = "Required reviewers count not met"
ComplianceStatus = "NON_COMPLIANT"
ComplianceStatusReason = "The record is non-compliant because the required number of reviewers is not present for the user."
```

**OutputFile:**

```json
[
  {
    "UserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering",
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}],
    "requested_reviewers_count": 2,
    "ValidationStatusCode": "REQ_REV_CNT_MET",
    "ValidationStatusNotes": "Required reviewers count met",
    "ComplianceStatus": "COMPLIANT",
    "ComplianceStatusReason": "The record is compliant because the required number of reviewers is present for the user."
  },
  {
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [{"login": "Reviewer3"}],
    "requested_reviewers_count": 1,
    "ValidationStatusCode": "REQ_REV_CNT_NT_MET",
    "ValidationStatusNotes": "Required reviewers count not met",
    "ComplianceStatus": "NON_COMPLIANT",
    "ComplianceStatusReason": "The record is non-compliant because the required number of reviewers is not present for the user."
  }
]
```

---

**Example 2:**

You can also use more complex conditions involving multiple fields or logical expressions:

```toml
[[AddColumn.ByCondition]]
Condition = "<<inputfile1.Users>> contains 'JohnDanie' and <<inputfile1.requested_reviewers_count>> > 1" # Check if 'JohnDanie' is in Users list and requested_reviewers_count > 1

[[AddColumn.ByCondition.True]]
ValidationStatusCode = "VALID_USER"
ValidationStatusNotes = "User is valid and has enough reviewers."
ComplianceStatus = "COMPLIANT"
ComplianceStatusReason = "The user has sufficient reviewers and meets the criteria."

[[AddColumn.ByCondition.False]]
ValidationStatusCode = "INVALID_USER"
ValidationStatusNotes = "User is either missing or has insufficient reviewers."
ComplianceStatus = "NON_COMPLIANT"
ComplianceStatusReason = "The user is either missing or does not meet the required number of reviewers."
```

---

#### 2. **Update Column**

The `UpdateColumn` section allows you to modify the values of existing columns in your `InputFile1` in different methods 

##### **Method 1 - Update Existing Columns**

Replaces the existing column value with another existing column value mentioned by the user.

**Syntax:**
```toml
[UpdateColumn]
"ExistingColumn" = "<<path_to_existing_column>>"
```

**Syntax explanation:**

 The **ExistingColumn** value will be updated with the value referring to the column the user mentioned.


**Example:**

**InputFile1:**

```json
[
  {
    "UserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering",
    "ResourceName" : "N/A",
    "ResourceID" : "N/A"
  },
  {
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "ResourceName" : "N/A",
    "ResourceID" : "N/A"
  }
]
```


**TransformConfigFile:**

```toml
[UpdateColumn]
"ResourceName" = "<<inputfile1.UserName>>"
"ResourceID" = "<<inputfile1.UserID>>"
```

**Output Example:**

```json
[
  {
    "ResourceName": "JohnDanie",
    "ResourceID": "43893443",
    "Department": "Engineering",
    "UserName": "JohnDanie",
    "UserID": "43893443",
  },
  {
    "ResourceName": "JosephAntony",
    "ResourceID": "43532253",
    "Department": "Marketing",
    "UserName": "JosephAntony",
    "UserID": "43532253",
  }
]
```

---

##### **Method 2 - Concatenate Values in a Column**

Use the `Concat` operation to add additional text to the values of an existing column. You can define the position where the new value will be placed—either at the start or at the end of the original value.

**Syntax:**
```toml
[[UpdateColumn.Concat]]
ColumnName = ""
ConcatValue = ""
Position = ""  # Options: "Start", "End"
```

**Syntax explanation:**
- **ColumnName**: The column whose value you want to modify.
- **ConcatValue**: The value to concatenate.
- **Position**: Defines where the concatenation should happen. Choose either "Start" (to prepend) or "End" (to append).


**Example 1:**

**InputFile1:**
```json
[
  {
    "role": "Admin"
  },
  {
    "role": "User"
  }
]
```

**TransformConfigFile:**
```toml
[[UpdateColumn.Concat]]
ColumnName = "<<inputfile1.role>>"
ConcatValue = "Role: "
Position = "Start"  # Options: "Start", "End"
```

**Output Example:**
```json
[
  {
    "role": "Role: Admin"
  },
  {
    "role": "Role: User"
  }
]
```


**Example 2:**

**InputFile1:**
```json
[
  {
    "role": "Admin"
  },
  {
    "role": "User"
  }
]
```

**TransformConfigFile:**
```toml
[[UpdateColumn.Concat]]
ColumnName = "<<inputfile1.role>>"
ConcatValue = " Role"
Position = "End"  # Options: "Start", "End"
```

**Output Example:**
```json
[
  {
    "role": "Admin Role"
  },
  {
    "role": "User Role"
  }
]
```
---

##### **Method 3 - Split Values in a Column**

The `Split` operation divides the values in a column based on a delimiter. You can specify the index of the part you want to extract from the split result.


**Syntax:**
```toml
[[UpdateColumn.Split]]
Source = ""
Delimiter = ""
Index = 0
```

**Syntax explanation:**
- **Source**: The column or field whose value you want to split.
- **Delimiter**: The character used to split the value.
- **Index**: The index of the part you want to extract (starting from 0). Index should be integer.

**Example:**

**InputFile1:**
```json
[
  {
    "project": "2024/Tech/Final/Overview"
  },
  {
    "project": "2024/Marketing/Launch/Intro"
  }
]
```

**TransformConfigFile:**
```toml
[[UpdateColumn.Split]]
Source = "<<inputfile1.project>>"
Delimiter = "/"
Index = 3
```

**OutputFile:**
```json
[
  {
    "project": "Overview"
  },
  {
    "project": "Intro"
  }
]
```

---

##### **Method 4 - Replace Values in a Column**

The `Replace` operation allows you to find a match within a column's values using a regular expression and replace it with a new value.

**Syntax:**
```toml
[[UpdateColumn.Replace]]
ColumnName = ""
Regex = ""
ReplaceValue = ""
```

**Syntax explanation:**
- **ColumnName**: The column in which you want to perform the replacement.
- **Regex**: The regular expression pattern to match.
- **ReplaceValue**: The value that will replace the matched value.

**Example:**

**InputFile1:**
```json
[
  {
    "project": "2024/Tech/Final/Overview"
  },
  {
    "project": "2024/Marketing/Launch/Intro"
  }
]
```

**TransformConfigFile:**
```toml
[[UpdateColumn.Replace]]
ColumnName = "<<inputfile1.project>>"
Regex = "Tech"
ReplaceValue = "Engineering"
```

**OutputFile:**
```json
[
  {
    "project": "Engineering"
  },
  {
    "project": "2024/Marketing/Launch/Intro"
  }
]
```

---

##### **Method 5 - Change Path for Data**

The `ChangePath` operation is used to move or transform data between different fields, including fields that are part of nested structures (e.g., dictionaries or lists).

**Syntax:**
```toml
[[UpdateColumn.ChangePath]]
Source = ""
Target = ""
Type = ""
```

**Syntax explanation:**
- **Source**: The source field containing the data you want to move. 
- **Target**: The Target field where the data will be moved and field should be List or dict. If target field is list that should be list of dicts.
- **Type**: This is mandatory if the Target field is a list. It defines the operation to apply when moving data. Use `"Append"` to add the data to the list, or `"Concat"` to merge the data with the existing value. If the Type is not mentioned, no changes will be reflected in the output file


**Example1: Target PathType - List, Type - Append**


**InputFile1:**
```json
[
  {
    "address": {
      "zipcode": "12345",
      "previous_addresses": [
        {
          "location" : "us-west"
        }
      ]
    }
  },
  {
    "address": {
      "zipcode": "67890",
      "previous_addresses": [
        {
          "location" : "us-west"
        }
      ]
    }
  }
]
```

**TransformConfigFile:**
```toml
[[UpdateColumn.ChangePath]]
Source = "<<inputfile1.address.zipcode>>"
Target = "<<inputfile1.address.previous_addresses>>"
Type = "Append"
```

**OutputFile:**
```json
[
  [
  {
    "address": {
      "zipcode": "12345",
      "previous_addresses": [
        {
          "location" : "us-west"
        },
        {
          "zipcode" : "12345"
        }
      ]
    }
  },
  {
    "address": {
      "zipcode": "67890",
      "previous_addresses": [
        {
          "location" : "us-west"
        },
        {
          "zipcode" : "12345"
        }
      ]
    }
  }
]
]
```


**Example2: Target PathType - List, Type - Concat**


**InputFile1:**
```json
[
  {
    "address": {
      "zipcode": "12345",
      "previous_addresses": [
        {
          "location" : "us-west"
        }
      ]
    }
  },
  {
    "address": {
      "zipcode": "67890",
      "previous_addresses": [
        {
          "location" : "us-west"
        }
      ]
    }
  }
]
```

**TransformConfigFile:**
```toml
[[UpdateColumn.ChangePath]]
Source = "<<inputfile1.address.zipcode>>"
Target = "<<inputfile1.address.previous_addresses>>"
Type = "Concat"
```

**OutputFile:**
```json
[
  [
  {
    "address": {
      "zipcode": "12345",
      "previous_addresses": [
        {
          "location" : "us-west",
          "zipcode" : "12345"
        }
      ]
    }
  },
  {
    "address": {
      "zipcode": "67890",
      "previous_addresses": [
        {
          "location" : "us-west",
          "zipcode" : "12345"
        }
      ]
    }
  }
]
]
```


**Example3: Target PathType - Dict**


**InputFile1:**
```json
[
  {
    "address": {
      "zipcode": "12345",
      "previous_addresses": 
        {
          "location" : "us-west"
        }
    }
  },
  {
    "address": {
      "zipcode": "67890",
      "previous_addresses": 
        {
          "location" : "us-west"
        }
    }
  }
]
```


**TransformConfigFile:**
```toml
[[UpdateColumn.ChangePath]]
Source = "<<inputfile1.address.zipcode>>"
Target = "<<inputfile1.address.previous_addresses>>"
Type = ""
```

**OutputFile:**
```json
[
  [
  {
    "address": {
      "zipcode": "12345",
      "previous_addresses": 
        {
          "location" : "us-west",
          "zipcode" : "12345"
        }
      
    }
  },
  {
    "address": {
      "zipcode": "67890",
      "previous_addresses": 
        {
          "location" : "us-west",
          "zipcode" : "12345"
        }
    }
  }
]
]
```
---


#### 3. **Delete Column**

You can remove one or more columns using the `DeleteColumn` operation.

**Syntax:**
```toml
[DeleteColumn]
"ColumnList" = "Column1,Column2,Column3"
```

**Syntax explanation:**
- **ColumnList**: A comma-separated list of column names to delete.

**Example:**

**InputFile1:**
```json
[
  {
    "UserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering",
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}]
  },
  {
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [{"login": "Reviewer3"}, {"login": "Reviewer4"}]
  }
]
```

**TransformConfigFile:**
```toml
[DeleteColumn]
"ColumnList" = "Users,requested_reviewers"
```

**OutputFile:**
```json
[
  {
    "ResourceName": "JohnDanie",
    "ResourceID": "43893443",
    "Department": "Engineering"
  },
  {
    "ResourceName": "JosephAntony",
    "ResourceID": "43532253",
    "Department": "Marketing"
  }
]
```

---

#### 4. **Reorder Columns**

The `ReorderColumn` operation allows you to change the order of the columns in the output file. Only the columns mentioned in reorder will be present in outputfile.

**Syntax:**
```toml
[ReorderColumn]
"ColumnList" = "Column1,Column2,Column3"
```

**Syntax explanation:**
- **ColumnList**: A comma-separated list of columns in the desired order.


**Example:**

**InputFile1:**
```json
[
  {
    "Department": "Engineering",
    "UserID": "43893443",
    "UserName": "JohnDanie",    
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}],
    "HOD" : "Peter Will",
    "College" : "Oxford university"
  },
  {
    
    "Department": "Marketing",
    "UserID": "43532253",
    "UserName": "JosephAntony",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [{"login": "Reviewer3"}, {"login": "Reviewer4"}],
    "HOD" : "Peter Will",
    "College" : "Oxford university"
  }
]
```

**TransformConfigFile:**
```toml
[ReorderColumn]
"ColumnList" = "UserName,UserID,Department,Users,requested_reviewers"
```

**OutputFile:**
```json
[
  {
    "UserName": "JohnDanie",    
    "UserID": "43893443",
    "Department": "Engineering",
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}]
  },
  {    
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [{"login": "Reviewer3"}, {"login": "Reviewer4"}]
  }
]
```

---

#### 5. **Remove Duplicates**

The RemoveDuplicates operation allows you to remove duplicate rows based on specific columns.

**Syntax:**
```toml
[RemoveDuplicates]
"ColumnList" = "Column1,Column2,Column3"
```

**Syntax explanation:**
- **ColumnList**: A comma-separated list of columns used to identify duplicates. Rows with the same values in these columns will be considered duplicates and removed.

**Example:**

**InputFile1:**
```json
[
  {
    "Department": "Engineering",
    "UserID": "43893443",
    "UserName": "JohnDanie",    
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}]
  },
  {
    "Department": "Marketing",
    "UserID": "43532253",
    "UserName": "JosephAntony",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [{"login": "Reviewer3"}, {"login": "Reviewer4"}]
  },
  {
    "Department": "Engineering",
    "UserID": "43893443",
    "UserName": "JohnDanie",    
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}]
  }
]
```

**TransformConfigFile:**
```toml
[RemoveDuplicates]
"ColumnList" = "UserID,UserName"
```

**OutputFile:**
```json
[
  {
    "Department": "Engineering",
    "UserID": "43893443",
    "UserName": "JohnDanie",    
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}]
  },
  {
    "Department": "Marketing",
    "UserID": "43532253",
    "UserName": "JosephAntony",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [{"login": "Reviewer3"}, {"login": "Reviewer4"}]
  }
]
```

---

### **InputFile2**

This input file is optional and is used to provide additional context to the data in `InputFile1`, such as mapping one piece of information (e.g., a user) to another related piece (e.g., a manager).

**Usage in TransformConfigFile:**

**Syntax:**
```toml
[[AddColumn.ByMap]]
ColumnName = ""         
Source = ""
Target = ""
TargetMapping = ""
```

**Syntax explanation:**
- **ColumnName**: The name of the new column.
- **Source**: The source column in the InputFile1(e.g., `<<inputfile1.UserName>>`).
- **Target**: The target column in the InputFile2 (e.g., `<<inputfile2.Users>>`).
- **TargetMapping**: The target mapping column in the InputFile2 (e.g., `<<inputfile2.Manager>>`).

**Example:**

**InputFile2:**
```csv
Users,Manager
JohnDanie,PerterRutherFord
JosephAntony,PerterRutherFord
```

The supported type for **InputFile2** is `CSV`. In this example,  **InputFile2** contains two columns:

- **Users**: This column contains the names of users.
- **Manager**: This column contains the names of the respective managers for the users listed in the **Users** column.


**InputFile1:**
```json
[
  {
    "UserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering",
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}]
  },
  {
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [{"login": "Reviewer3"}, {"login": "Reviewer4"}]
  }
]
```

**TransformConfigFile:**
```toml
[[AddColumn.ByMap]]
ColumnName = "Manager"         
Source = "<<inputfile1.UserName>>"
Target = "<<inputfile1.Users>>"
TargetMapping = "<<inputfile1.Manager>>"
```

By using above mapping, the **Manager** column is added to **InputFile1**, where each user’s manager will be populated based on the mapping provided in **InputFile2**.


**OutputFile:**
```json
[
  {
    "UserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering",
    "Users": ["JohnDanie", "JaneDoe"],
    "requested_reviewers": [{"login": "Reviewer1"}, {"login": "Reviewer2"}],
    "Manager" : "PerterRutherFord"
  },
  {
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing",
    "Users": ["JosephAntony", "JackSmith"],
    "requested_reviewers": [{"login": "Reviewer3"}, {"login": "Reviewer4"}],
    "Manager" : "PerterRutherFord"
  }
]
```

---


## **OutputsSection**

### **OutputFile:**
The output file that contains the transformed data. 

### **LogFile:**
The log file that contains details about any errors or issues during the transformation process, or the log from the previous task.

---