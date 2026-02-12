### **Name**: FetchGithubOrgMembers

### **Purpose** : 
- The purpose of this task is to fetch the list of members in a specified GitHub organization and upload the data to MinIO so that other controls can utilize this evidence.  

### **InputsAndOutputsStructure**  
    - Inputs :
       - OrganizationName          : [MANDATORY] The string contains organization names separated by commas.
    - Outputs :
       - GitHubOrganizationMembers : The file that contains the data of organization members.
       - LogFile                   :  The logfile contains error logs for any issues encountered during execution.  

### **InputsSection**  
    1. OrganizationName (Required) 
        – The name of the GitHub organization whose members need to be retrieved.  
        - Example: "SampleOrg1, SampleOrg2"

### **OutputsSection**  
    1. GitHubOrganizationMembers – The list of members in the specified GitHub organization.  
    2. LogFile – Contains error logs for any issues encountered during execution.  

### **NOTE:**  
   - If a non-owned organization is provided, errors will be logged.  
   - If both an owned and a non-owned organization name are provided as input, an output file will be generated for the owned organization, and a LogFile will be created for the non-owned organization.