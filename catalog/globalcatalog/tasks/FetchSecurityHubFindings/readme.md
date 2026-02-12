The purpose of this task is to retrieve  security-related data from AWS Security Hub. This task automates the process of making API calls to AWS Security Hub to fetch security findings, enabling users to gather detailed information about vulnerabilities, threats, and compliance status within their cloud environment. The task processes the input parameters like Regions, AWSProductName and FindingsRecordState, and outputs the findings in a structured format, such as JSON, for further analysis or integration into security dashboards and incident response tools

### **InputsAndOutputsStructure**:

1. Inputs:
    - Region: [MANDATORY]  STRING  # A list of regions can be included using square brackets [ ]
    - AWSProductName: [MANDATORY] STRING 
    - FindingsRecordState: [MANDATORY] STRING

2. Outputs:
    - SecurityHubFindingsFile:  <<MINIO_FILE_PATH>>
    - LogFile:  <<MINIO_FILE_PATH>>


### **InputsSection**:
    
1. Region (Mandatory)

    - 'Region'  refers to the specific AWS geographical area where your AWS Security Hub data is stored and processed

    - Example: ["us-east-1", "eu-west-1", "ap-southeast-2"] a list of regions can be included using square brackets [ ] or [ "us-east-1" ] a single region inside the square brackets [ ]
        

2. AWSProductName (Mandatory)

    - 'AWSProductName' refers to the specific AWS product or service for which you want to fetch security findings from AWS Security Hub. In this we use Security Hub service to fetch the findings

    - Example: "Security Hub" is a AWS product

    
3. FindingsRecordState (Mandatory)
    - 'FindingsRecordState' refers to the current state of a security finding in AWS Security Hub.

    - Example: "ACTIVE" is a Record State of the finding
        


### **OutputsSection**:

1. SecurityHubFindingsFile 
    - This file contains the findings that matched the filters specified in the request such as Region, AWSProductName, and FindingsRecordState.

2. LogFile
    - This file records any errors that occur during a task, helping to track and troubleshoot issues.

