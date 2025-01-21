# TransformData - README

**TransformData**  allows you to perform a variety of column transformations on your input data files. You can add new columns, update existing columns, delete columns, and reorder columns. Below is a detailed guide on how to use these features effectively.

---

### **Inputs and Outputs Structure**

#### **Inputs:**
- **InputFile1**:  The input file to be transformed. [MANDATORY]

- **TransformConfigFile**:  The toml file containing the transformation configuration. [MANDATORY]

- **InputFile2**: This input file is an optional file used to add additional context to the data in **InputFile1**, such as mapping one piece of information (e.g., a user) to another related piece of information (e.g., a manager). This file typically contains data that helps establish relationships or enrich the data from **InputFile1**. [OPTIONAL]

- **LogFile**:  - This field is required only when this task is not acting as Task1 in the rule. Generally, when the previous task has a 'LogFile,' we will map that logfile to this input in the NoCode UI. If the 'LogFile' is empty, the 'TransformData' task will be processed. Otherwise, it will simply pass the previous task's 'LogFile' to the 'TransformData' task's 'LogFile. [OPTIONAL]

#### **Outputs:**
- **OutputFile**:  The output file that contains the transformed data.

- **LogFile**:  The log file that contains details about any errors or issues during the transformation process, or the log from the previous task.

---

## InputFile1 - Explanation

File that requires transformations. It typically contains the raw data to be processed and transformed according to the rules specified in the TransformConfigFile. The file format for **InputFile1** is  JSON.
The data in **InputFile1** can include multiple columns and values, which can be modified, added, deleted, or reordered based on the transformations defined in the TransformConfigFile.

### Example for **InputFile1**:
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

## TransformConfigFile - Explanation

### 1. **Add Column**

The `AddColumn` operation allows you to add new columns to your data in different ways. 

---

#### Adding a Column with desired values
You can add a new column with a below structure:

```toml
[AddColumn]
"NewColumn" = "value"
```

- **NewColumn**: The name of the new column.
- **value**: The possible ways for giving value in below structure

              - fixed value: "System" = "aws"
              - value from InputFile1: "SystemUserName" = "<<inputfile1.UserName>>" or <<UserName>>
              - Replace placeholders from InputFile1: "ResourceURL" = https://portal.azure.com/users/<<inputfile1.UserID>> 

##### **Sample Example**:

##### **InputFile1**:
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

##### **Config**:
```toml
[AddColumn]
"System" = "aws"
"SystemUserName" = "<<inputfile1.UserName>>"
"ResourceURL" = "https://portal.azure.com/users/<<inputfile1.UserID>>>"
```

##### **OutputFile**:
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

#### Adding a Column Using a Function
You can add a column by applying a function to an existing column. 

Note: Supported Functions - 'Length', 'CurrentDateTime'


```toml
[[AddColumn.ByFunction]]
ColumnName = ""         
Source = ""
Function = ""
```

- **ColumnName**: The name of the new column.
- **Source**: The path to the existing column (e.g., `<<inputfile1.Users>>`).
- **Function**: The transformation function to apply (e.g., `Length`).


##### **Sample Example** for function 'Length':

##### **InputFile1**:
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

##### **Config**:
```toml
[[AddColumn.ByFunction]]
ColumnName = "TotalUsers"         
Source = "<<inputfile1.Users>>"
Function = "Length"
```

##### **OutputFile**:
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


##### **Sample Example** for function 'CurrentDateTime':


##### **InputFile1**:
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

##### **Config**:
```toml
[[AddColumn.ByFunction]]
ColumnName = "EvaluationTime"         
Source = ""
Function = "CurrentDateTime"
```

##### **OutputFile**:
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

Note: Format for 'CurrentDateTime' supported is %Y-%m-%dT%H:%M:%S.%fZ

---

#### Adding a Column as an Object

You can add a new column by constructing an object from multiple fields in an existing record. The values for the new object can be derived from multiple columns, and they will be combined into a single object.

##### Configuration:

```toml
[[AddColumn.AsObject]]
ColumnName = ""                # Name of the new column
ObjectValues = ""               # Comma-separated paths to the fields to include in the object
```

- **ColumnName**: The name of the new column.
- **ObjectValues**: A comma-separated list of paths to the fields in the existing record that should be included in the new object. Ensure there are no spaces between the paths.

##### Sample Example for 'AsObject':

##### InputFile1:
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

##### Config:
```toml
[[AddColumn.AsObject]]
ColumnName = "AdditionalInfo"
ObjectValues = "<<inputfile1.UserID>>,<<inputfile1.Role>>,<<inputfile1.Permission>>,<<inputfile1.Address>>,<<inputfile1.Profile.Skills>>"
```

##### OutputFile:
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

#### Adding a Column Using Mapping
You can create a new column by mapping data from one file to another. For example, mapping user names to managers:

```toml
[[AddColumn.ByMap]]
ColumnName = ""         
Source = ""
Target = ""
TargetMapping = ""
```

- **ColumnName**: The name of the new column.
- **Source**: The source column in the InputFile1(e.g., `<<inputfile1.UserName>>`).
- **Target**: The target column in the InputFile2 (e.g., `<<inputfile2.Users>>`).
- **TargetMapping**: The target mapping column in the InputFile2 (e.g., `<<inputfile2.Manager>>`).

##### **Sample Example**:

##### **InputFile1**:
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

##### **InputFile2**:
```csv
Users,Manager
JohnDanie,PerterRutherFord
JosephAntony,PerterRutherFord
```

##### **Config**:
```toml
[[AddColumn.ByMap]]
ColumnName = "Manager"         
Source = "<<inputfile1.UserName>>"
Target = "<<inputfile1.Users>>"
TargetMapping = "<<inputfile1.Manager>>"
```



##### Sampe **OutputFile**:
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

#### Adding a Column as a List
You can add a column as a list with values extracted from a source file or provided as a predefined list:

```toml
[[AddColumn.AsList]]
ColumnName = ""         
Source = ""
Target = ""

[[AddColumn.AsList]]
ColumnName = ""         
ListData = []
```

- **ColumnName**: The name of the new column.
- **Source**: The path to the data in the source file (e.g., `<<inputfile1.requested_reviewers>>`).
- **Target**: The path to a specific field within the list (e.g., `<<Source.login>>`).
- **ListData**: A predefined list of values to populate the new column (e.g., `["data1", "data2", "data3"]`).

##### **Sample Example**:

##### **InputFile1**:
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

##### **Config**:
```toml
[[AddColumn.AsList]]
ColumnName = "PRReviewers"                      # New column name "PRReviewers"
Source = "<<inputfile1.requested_reviewers>>"   # Source column (requested_reviewers). This should be a List.
Target = "<<Source.login>>"                     # Extracting the "login" field from each object in the list.
# As a result, the column 'PRReviewers' will be added as a list that contains the values of all targets from the source list.

[[AddColumn.AsList]]
ColumnName = "DefaultList"                      # New column name "DefaultList"
ListData = ["data1", "data2", "data3"]          # ListData should be an array.
# As a result, the column 'DefaultList' will be added as a list that contains the values of all ListData.
```

##### **OutputFile**:
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

### Adding a Column by Condition

You can add a column by condition:

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

- **Condition**: A condition that needs to be checked.

As a result, new columns will be added based on whether the condition evaluates to `True` or `False`.

#### Supported Conditions:

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

- **List or String Checks**: 
  - `<<inputfile1.requested_reviewers_count>> > 1` (e.g., check if the count is greater than 1)
  - `<<inputfile1.Users>> contains 'JohnDanie'` (e.g., check if a specific user exists in the `Users` list)

#### Example Usage:

##### **InputFile1**:

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

##### **Config**:

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

##### **OutputFile**:

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

### **Advanced Example: Complex Conditions**

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

### 2. **Update Column**

The `UpdateColumn` section allows you to modify or transform the values of existing columns in your dataset. You can replace, concatenate, split, or update specific values using various operations. Additionally, you can create new columns by constructing objects from multiple fields.

---

#### Syntax Overview

```toml
[UpdateColumn]
"NewColumnName" = "<<ExistingColumnName>>"

[[UpdateColumn.Concat]]
ColumnName = "SomeColumn"
ConcatValue = "SomePrefix"
Position = "Start" # Options: "Start", "End"

[[UpdateColumn.Split]]
Source = "<<inputfile1.some_field>>"
Delimiter = ","
Index = 0

[[UpdateColumn.Replace]]
ColumnName = "SomeColumn"
Regex = "pattern_to_match"
ReplaceValue = "new_value"

[[UpdateColumn.ChangePath]]
Source = "<<inputfile1.some_field>>"
Target = "<<inputfile1.new_field>>"
Type = "Append" # Options: "Concat", "Append"

[[AddColumn.AsObject]]
ColumnName = "NewObjectColumn"
ObjectValues = "<<inputfile1.Field1>>,<<inputfile1.Field2>>,<<inputfile1.Field3>>"
```

---

#### Detailed Configuration

##### **Update Existing Columns**
The `UpdateColumn` operation is used to create new columns based on the values of existing columns. This operation essentially copies data from one column to another.

**Example:**

```toml
[UpdateColumn]
"ResourceName" = "<<UserName>>"
"ResourceID" = "<<UserID>>"
```

- **ResourceName**: Will be populated with the value from the `UserName` column.
- **ResourceID**: Will be populated with the value from the `UserID` column.

**Input Example:**

```json
[
  {
    "UserName": "JohnDanie",
    "UserID": "43893443",
    "Department": "Engineering"
  },
  {
    "UserName": "JosephAntony",
    "UserID": "43532253",
    "Department": "Marketing"
  }
]
```

**Output Example:**

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

##### **Concatenate Values in a Column**
Use the `Concat` operation to add additional text to the values of an existing column. You can define the position where the new value will be placed—either at the start or at the end of the original value.

**Example:**

```toml
[[UpdateColumn.Concat]]
ColumnName = "role"
ConcatValue = "Role: "
Position = "Start"  # Options: "Start", "End"
```

- **ColumnName**: The column whose values you want to modify.
- **ConcatValue**: The value to concatenate.
- **Position**: Defines where the concatenation should happen. Choose either "Start" (to prepend) or "End" (to append).

**Input Example:**

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

##### **Split Values in a Column**
The `Split` operation divides the values in a column based on a delimiter. You can specify the index of the part you want to extract from the split result.

**Example:**

```toml
[[UpdateColumn.Split]]
Source = "<<inputfile1.project>>"
Delimiter = "/"
Index = 3
```

- **Source**: The column or field whose value you want to split.
- **Delimiter**: The character used to split the value.
- **Index**: The index of the part you want to extract (starting from 0).

**Input Example:**

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

**Output Example:**

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

##### **Replace Values in a Column**
The `Replace` operation allows you to find a match within a column's values using a regular expression and replace it with a new value.

**Example:**

```toml
[[UpdateColumn.Replace]]
ColumnName = "project"
Regex = "Tech"
ReplaceValue = "Engineering"
```

- **ColumnName**: The column in which you want to perform the replacement.
- **Regex**: The regular expression pattern to match.
- **ReplaceValue**: The value that will replace the matched value.

**Input Example:**

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

**Output Example:**

```json
[
  {
    "project": "2024/Engineering/Final/Overview"
  },
  {
    "project": "2024/Marketing/Launch/Intro"
  }
]
```

##### **Change Path for Data**
The `ChangePath` operation is used to move or transform data between different fields, including fields that are part of nested structures (e.g., dictionaries or lists).

**Example:**

```toml
[[UpdateColumn.ChangePath]]
Source = "<<inputfile1.address.zipcode>>"
Target = "<<inputfile1.address.previous_addresses>>"
Type = "Append"
```

- **Source**: The original field containing the data you want to move.
- **Target**: The destination field where the data will be moved.
- **Type**: Defines the operation to apply when moving data. Use `"Append"` to add the data to the list, or `"Concat"` to merge the data with the existing value.

**Input Example:**

```json
[
  {
    "address": {
      "zipcode": "12345",
      "previous_addresses": []
    }
  },
  {
    "address": {
      "zipcode": "67890",
      "previous_addresses": []
    }
  }
]
```

**Output Example (After Append):**

```json
[
  {
    "address": {
      "zipcode": "12345",
      "previous_addresses": ["12345"]
    }
  },
  {
    "address": {
      "zipcode": "67890",
      "previous_addresses": ["67890"]
    }
  }
]
```
---


### 3. **Delete Column**

You can remove one or more columns using the `DeleteColumn` operation.

#### Syntax:

```toml
[DeleteColumn]
"ColumnList" = "Column1,Column2,Column3"
```

- **ColumnList**: A comma-separated list of column names to delete.

##### **Sample Example**:

##### **InputFile1**:
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

##### **Config**:
```toml
[DeleteColumn]
"ColumnList" = "Users,requested_reviewers"
```

##### **OutputFile**:
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

### 4. **Reorder Columns**

The `ReorderColumn` operation allows you to change the order of the columns in the output file.

#### Syntax:

```toml
[ReorderColumn]
"ColumnList" = "Column1,Column2,Column3"
```

- **ColumnList**: A comma-separated list of columns in the desired order.


##### **Sample Example**:

##### **InputFile1**:
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

##### **Config**:
```toml
[ReorderColumn]
"ColumnList" = "UserName,UserID,Department,Users,requested_reviewers"
```

##### **OutputFile**:
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

### 5. **Remove Duplicates**

The RemoveDuplicates operation allows you to remove duplicate rows based on specific columns.

#### Syntax:

```toml
[RemoveDuplicates]
"ColumnList" = "Column1,Column2,Column3"
```

- **ColumnList**: A comma-separated list of columns used to identify duplicates. Rows with the same values in these columns will be considered duplicates and removed.

##### **Sample Example**:

##### **InputFile1**:
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

##### **Config**:
```toml
[RemoveDuplicates]
"ColumnList" = "UserID"
```

##### **OutputFile**:
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

## **InputFile2** - Explanation

#### **Example Structure of InputFile2:**

```csv
Users,Manager
JohnDanie,PerterRutherFord
JosephAntony,PerterRutherFord
```

In this example, **InputFile2** contains two columns:

- **Users**: This column contains the names of users.
- **Manager**: This column contains the names of the respective managers for the users listed in the **Users** column.

The file essentially maps each user to their respective manager. This mapping is often useful when you want to enrich **InputFile1** with manager information, which might be applied during a transformation process.

#### **Usage in Transformations:**
You can reference **InputFile2** in the transformation configuration file, typically in the **AddColumn.ByMap** operation, to map a user's name (from **InputFile1**) to their respective manager (from **InputFile2**).

For instance, if you wanted to add a **Manager** column to **InputFile1** using the data from **InputFile2**, you could use the following configuration:

```toml
[[AddColumn.ByMap]]
ColumnName = "Manager"         
Source = "<<inputfile1.UserName>>"
Target = "<<inputfile2.Users>>"
TargetMapping = "<<inputfile2.Manager>>"
```

- **Source**: Refers to the column in **InputFile1** that holds the user names (e.g., `<<inputfile1.UserName>>`).
- **Target**: Refers to the column in **InputFile2** that also holds the user names (e.g., `<<inputfile2.Users>>`).
- **TargetMapping**: Specifies the column in **InputFile2** containing the manager names (e.g., `<<inputfile2.Manager>>`).

By using this mapping, the **Manager** column is added to **InputFile1**, where each user’s manager will be populated based on the mapping provided in **InputFile2**.

---

## Notes

- Be sure to define the paths to columns correctly using the format `<<InputFile.Path>>`. For example, if referencing a column in `InputFile1`, use `<<inputfile1.Path>>`.
- The operations in the configuration file are executed sequentially, so additions will happen before updates, deletions, or reordering.
  
---