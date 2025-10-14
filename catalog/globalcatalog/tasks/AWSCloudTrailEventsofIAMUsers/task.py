from typing import overload 
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from applicationtypes.awsappconnector import awsappconnector
from compliancecowcards.utils import cowdictutils
import json
import uuid
import pandas as pd
from datetime import datetime
import urllib.parse
import os
import toml

class Task(cards.AbstractTask):

    def execute(self) -> dict:

        val_err_list = self.validate()
        if val_err_list:
            return self.upload_log_file(self.add_key_in_list(val_err_list))
        
        error_list =[]

        # Download 'EventFile'
        event_file_df, error = self.download_csv_file_from_minio_as_df(
            self.task_inputs.user_inputs.get('EventFile'))
        if error:
            return self.upload_log_file(self.add_key_in_list([f"Error while downloading 'EventFile'. {error}"]))
        if event_file_df.empty:
            error_list.append("Provided 'EventFile' is empty. Please provide a valid 'EventFile'")
        
        # Download 'ResourceFile'
        toml_bytes, error = self.download_file_from_minio(self.task_inputs.user_inputs.get('ResourceFile'))
        if error:
            return self.upload_log_file(self.add_key_in_list([f"Error while downloading 'ResourceFile'. {error}"]))
        try:
            toml_data = toml.loads(toml_bytes.decode('utf-8'))
        except (UnicodeDecodeError, toml.TomlDecodeError) as error:
            return self.upload_log_file(self.add_key_in_list([f"Error while processing 'ResourceFile' toml data. {str(error)}"]))
        if not toml_bytes:
            error_list.append("Provided 'ResourceFile' is empty. Please provide a valid 'ResourceFile'")
        
        # Not proceeding if 'EventFile' or 'ResourceFile' is empty
        if error_list:
            return self.upload_log_file(self.add_key_in_list(error_list))
        
        # Validate 'EventFile' and 'ResourceFile'
        check_list = self.check_csv_file(event_file_df)
        if check_list:
            for item in check_list:
                error_list.append(item)
        include_resource_criteria, exclude_resource_criteria, err = self.check_toml_file(toml_data)
        if err:
            error_list.append(err)

        if error_list:
            return self.upload_log_file(self.add_key_in_list(error_list))
        
        resource_types = event_file_df["ResourceType"].unique().tolist()

        # Fetch include and exclude resource details based on the services
        include_resources_with_service, exclude_resources_with_service, error_list = self.handle_include_and_exclude_resources(
            include_resource_criteria, exclude_resource_criteria, resource_types
        )
        if error_list:
            return self.upload_log_file(self.add_key_in_list(error_list))

        # AWS app creation
        app = awsappconnector.AWSAppConnector(
            user_defined_credentials=awsappconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials),
            region=self.task_inputs.user_inputs.get("Region")
        )

        # Filter the events that is required
        event_file_df["IsRequired"] = event_file_df["IsRequired"].str.strip().str.lower()
        filtered_event_file_df = event_file_df.loc[(event_file_df['IsRequired'] == 'yes')]

        final_events = []
        no_service_details_found = []

        aws_users = app.get_user_names()

        # Process 'EventFile.csv' input file
        event_file_list = filtered_event_file_df.to_dict(orient='records')
        for event in event_file_list:
            
            service = event.get('ResourceType') 
            events = event.get('EventNames')
            users = event.get('UserNames')
            if users == "*":
                if not aws_users:
                    return self.upload_log_file([{"Error": "Error occured while fetching aws users list"}])
                users = aws_users
            else:
                users = users.split(",")
            
            event_info = []
            if service:
                look_up_attribute = [{'AttributeKey': 'ResourceType', 'AttributeValue': service}]
                event_history, error = app.look_up_events(self.task_inputs.from_date, self.task_inputs.to_date, look_up_attribute)
                if error:
                    error_list.append({"Error" : f"Failed to fetch event details for 'ResourceType' - {service}. {str(error)}"})
                    continue
                if not event_history:
                    no_service_details_found.append(service)
                    continue
                if event_history:
                    if events !="*":
                        event_history_df = pd.DataFrame(event_history)
                        present_event_names = event_history_df['EventName'].unique()
                        event_names_list = events.split(",")
                        missing_event_names = set(event_names_list) - set(present_event_names)
                        if missing_event_names:
                            error_list.append({"Error" : f"Failed to fetch following event(s) - {','.join(list(missing_event_names))}. ResourceType - {service}"})
                        filtered_df = event_history_df[event_history_df['EventName'].isin(event_names_list)]
                        filtered_list = filtered_df.to_dict(orient='records')
                        event_info = filtered_list 
                    else:
                        event_info = event_history
                    if users:
                        event_df = pd.DataFrame(event_info)
                        if event.get('UserNames') != "*":
                            event_user_names = event_df['Username'].unique()
                            missing_users = set(users) - set(event_user_names)
                            if missing_users:
                                error_list.append({"Error" : f"Failed to include following user(s) - {','.join(list(missing_users))}. ResourceType - {service}"})
                        filtered_df = event_df[event_df['Username'].isin(users)]
                        event_info = filtered_df.to_dict(orient='records')
                if event_info:
                    for info in event_info:
                        final_events.append(info)
                    
        no_service_details_found = list(set(no_service_details_found))

        if no_service_details_found:
            error_list.append({"Error" : f"No events matching the provided AWS credentials within the specified period for the ResourceType(s) - {', '.join(no_service_details_found)}"})
        if not final_events and error_list:
            return self.upload_log_file(error_list)
        if not final_events:
            return self.upload_log_file({"Error" : "No events found for provided AWS credentials within the specified period"})
        if no_service_details_found:
            for service in no_service_details_found:
                del include_resources_with_service[service]
                del exclude_resources_with_service[service]
        
        if final_events:
        
            # Generate Event file and resource file data
            std_events, std_resources , st_err_list = self.generate_std_data(app, final_events, include_resources_with_service, exclude_resources_with_service)
            if st_err_list:
                for err in st_err_list:
                    error_list.append(err)

            if not std_events and not std_resources and not st_err_list:
                return self.upload_log_file([{"Error" : "No events were found for the provided AWS credentials within the specified period."}])

            response = {}

            if error_list:
                result =  self.upload_log_file(error_list)
                if cowdictutils.is_valid_key(result, 'Error'):
                    return result
                response['LogFile'] = result['LogFile']
                
            if std_events:
                file_path, error = self.upload_df_as_parquet_file_to_minio(
                    df=pd.json_normalize(std_events),
                    file_name=f"AWSEvents-{str(uuid.uuid4())}")
                response['AWSEventDetails'] = file_path
                
            if std_resources:
                file_path, error = self.upload_df_as_parquet_file_to_minio(
                    df=pd.json_normalize(std_resources),
                        file_name=f"AWSResourceDetails-{str(uuid.uuid4())}")
                response['AWSResourceDetails'] = file_path

            return response

        return {"AWSEventDetails" : ""}

    def generate_std_data(self, app, events, include_resources_with_service, exclude_resources_with_service):

        std_events = []
        std_resources = []
        error_list = []
        
        # dict to track the event counts for each source
        resource_arn_map = {}

        # Sort events so that the final record is the latest record
        sorted_events = []
        if all('EventTime' in event for event in events):
            sorted_events = sorted(events, key=lambda x: x['EventTime'])
        
        if not sorted_events:
            return [], [], [{"Error" : "Sorting EventData based on DateTime has failed. Please contact support for more details."}]
        
        # Fetch account details since some resource ARNs require the account number
        account = ''
        identifier_details, errors = app.get_caller_identity()
        if errors:
            error_list.append({"Error" : error} for error in errors)
            return [], [], error_list
        if identifier_details.empty or "Account" not in identifier_details:
            return [], [], [{"Error" : "Failed to fetch account details for given AWS credentials"}]
        account = identifier_details['Account'][0]

        # To track resource that failed to include
        include_res_present = {}
        for service, resources in include_resources_with_service.items():
            include_res_present[service] = {}
            for resource in resources:
                resources = resource.split(",")
                include_resources_with_service[service] = resources
                for res in resources:
                    include_res_present[service][res] = False
        
        for service, resources in exclude_resources_with_service.items():
            for resource in resources:
                resources = resource.split(",")
                exclude_resources_with_service[service] = resources

        # loop events to generate a standard event evidence
        for event in sorted_events:
            
            event_id   = event['EventId'] if cowdictutils.is_valid_key(event, 'EventId') else "N/A"
            resources  = event['Resources'] if cowdictutils.is_valid_array(event, 'Resources') else []
            region     = event['Region'] if cowdictutils.is_valid_key(event, 'Region') else "N/A"
            user_name  = event['Username'] if cowdictutils.is_valid_key(event, 'Username') else "N/A"
            event_name = event['EventName'] if cowdictutils.is_valid_key(event, 'EventName') else "N/A"
            event_time = self.get_time_stamp(event, 'EventTime')
            event_region = event['Region'] if cowdictutils.is_valid_key(event, 'Region') else "N/A"

            # generate event url 
            event_url = ''
            resource_info_dict = {
                    awsappconnector.RESOURCE_TYPE: awsappconnector.CLOUD_TRAIL_EVENT, 
                    awsappconnector.RESOURCE_FIELD: event_id, 
                    awsappconnector.REGION_FIELD: region,}
            event_url, err = app.get_resource_url(resource_info_dict)
            if err:
                event_url = 'N/A'

            # Generate an ARN for the user who triggered this event
            user_arn = ""
            try:
                event_data = json.loads(event['CloudTrailEvent'])
                user_arn = event_data.get('userIdentity', {}).get('arn')
                # Convert non-standard capitalization into lowercase
                if user_arn and self.format_arn(user_arn):
                       user_arn = self.format_arn(user_arn)
                else:
                    user_arn = "N/A"
            except (json.JSONDecodeError, KeyError, ValueError):
                user_arn = "N/A"
            

            event_data = {
                        "System"            : "aws",
                        "Source"            : "compliancecow",
                        "ResourceID"        : event_id,
                        "ResourceLocation"  : event_region,
                        "ResourceTags"      : "N/A",
                        "ResourceType"      : "Event",
                        "ResourceName"      : event_name,
                        "ResourceURL"       : event_url,
                        "EventTime"         : event_time,
                        "AWSResourceInfo"   : resources,
                        "UserName"          : user_name,
                        "UserARN"           : user_arn,
                        "AWSResourceARN"    : '',
                    }
            
            # Loop resource data for generating resource evidence file
            if resources:

                for resource in resources:

                    resource_name = resource['ResourceName'] if cowdictutils.is_valid_key(resource, 'ResourceName') else "N/A"
                    resource_type = resource['ResourceType'] if cowdictutils.is_valid_key(resource, 'ResourceType') else "N/A"

                    #  check account info required for resource
                    aws_res_acc = ''
                    if self.is_account_req_for_arn(resource_type):
                        aws_res_acc = account
                    
                    # Generate ARN for resource modified in event
                    resource_arn, err = self.get_resource_arn(resource_id=resource_name,service=resource_type, account_id=aws_res_acc)
                    if err:
                        resource_arn = 'N/A'
                    # Convert non-standard capitalization into lowercase
                    if resource_arn :
                        resource_arn = self.format_arn(resource_arn)
                        
                    # Adding resource arn in event details
                    event_data['AWSResourceARN'] = resource_arn

                    if not resource_type in exclude_resources_with_service or not resource_type in include_resources_with_service:
                        continue
                        
                    # Update exclude_res_present dict, if the resource present in aws generated response    
                    if resource_name in exclude_resources_with_service[resource_type]:
                        continue

                    if not '*' in include_resources_with_service[resource_type] and not resource_name in include_resources_with_service[resource_type]:
                        continue

                    # Update include_res_present dict, if the resource present in aws generated response    
                    if resource_name in include_resources_with_service[resource_type]:
                        include_res_present[resource_type][resource_name] = True

                    # Update the event count in resource_arn_map for specific resource
                    if resource_arn in resource_arn_map:
                        resource_arn_map[resource_arn] += 1
                    else:
                        resource_arn_map[resource_arn] = 1                    
                        
                    # Generate URL for resource modified in event
                    resource_url = ''
                    if resource_name != "N/A" and resource_type != "N/A":
                                    
                        resource_info_dict = {
                                awsappconnector.RESOURCE_TYPE: self.get_url_service(resource_type), 
                                awsappconnector.RESOURCE_FIELD: resource_name.split('/')[-1] if resource_type == "AWS::KMS::Key" else resource_name, 
                                awsappconnector.REGION_FIELD: region,
                                }
                        resource_url, err = app.get_resource_url(resource_info_dict)
                        if err:
                            resource_url = "N/A"

                        resource_data = {
                            "System"            : "aws",
                            "Source"            : "compliancecow",
                            "ResourceID"        : resource_arn,
                            "ResourceLocation"  : event_region,
                            "ResourceTags"      : "N/A",
                            "ResourceType"      : resource_type,
                            "ResourceName"      : resource_name,
                            "ResourceURL"       : resource_url,
                            "LastEventName"     : event_name,
                            "LastEventID"       : event_id,
                            "LastEventTime"     : event_time,
                            "LastEventUserName" : user_name,
                            "LastEventUserARN"  : user_arn,
                            "NumberOfEvents"    : resource_arn_map[resource_arn],
                            }
                        
                        # Replace record with latest if more than one event occurred for resource
                        if resource_arn_map.get(resource_arn, 0) > 1:
                            for index, item in enumerate(std_resources):
                                if item.get('ResourceID') == resource_arn:
                                    std_resources[index] = resource_data
                        else:
                            std_resources.append(resource_data)

                    std_events.append(event_data)
                    
        # Appending to the error list for resources not found
        for service, resources in include_res_present.items():
            invalid_resources = []
            for resource, status in resources.items():
                if not status and resource != "*":  
                    invalid_resources.append(resource)
            if invalid_resources:
                error_list.append({"Error" : f"Failed to include following resource(s) - {', '.join(invalid_resources)}. ResourceType: {service}"})
        
        return std_events, std_resources, error_list
    
    
    def format_arn(self, arn):
        # Convert everything to lowercase except for the resource ID
        try:
            # arn:aws:service:region:account-id:resource-type/resource-id
            if '/' in arn:
                prefix, dynamic_part = arn.rsplit('/', 1)
                prefix_lower = prefix.lower()
                user_arn = f"{prefix_lower}/{dynamic_part}"
                return user_arn
            # arn:aws:service:region:account-id:resource-type:resource-id
            if ':' in arn:
                prefix, dynamic_part = arn.rsplit(':', 1)
                prefix_lower = prefix.lower()
                user_arn = f"{prefix_lower}:{dynamic_part}"
                return user_arn
        except IndexError:
            return ''
    

    def validate(self):
        task_inputs = self.task_inputs
        if not task_inputs:
            return ['Task input is missing']

        user_object = task_inputs.user_object
        if not (user_object and user_object.app and user_object.app.user_defined_credentials):
            return ['User defined credential is missing']

        error_list = []
        empty_attrs = []
        unsupported_str_fields = []
        unsupported_date_fields = []
        invalid_file_paths = []

        # Validate Region
        region = task_inputs.user_inputs.get('Region')
        if not region:
            empty_attrs.append('Region')
        elif not isinstance(region, list):
            error_list.append("'Region' type is not supported. Supported type: list")
        
        # Validate dates
        from_date = task_inputs.from_date
        to_date = task_inputs.to_date
        is_valid_dates = True
        
        if from_date is None:
            empty_attrs.append("From Date")
            is_valid_dates = False
        elif not isinstance(from_date, datetime):
            unsupported_date_fields.append("From Date")
            is_valid_dates = False

        if to_date is None:
            empty_attrs.append("To Date")
            is_valid_dates = False
        elif not isinstance(to_date, datetime):
            unsupported_date_fields.append("To Date")
            is_valid_dates = False

        if is_valid_dates and from_date > from_date:
            error_list.append(f"The 'From Date' must be earlier than the 'To Date'. Please give a valid 'From Date'")
        
        # Validate EventFile
        event_file_path = task_inputs.user_inputs.get('EventFile')
        if not event_file_path:
            empty_attrs.append('EventFile')
        elif not isinstance(event_file_path, str):
            unsupported_str_fields.append('EventFile')
        else:
            if not self.is_valid_url(event_file_path):
                invalid_file_paths.append('EventFile')
            else:
                extension = self.get_extension(event_file_path)
                if extension  != ".csv":
                    error_list.append(f"'EventFile' extension - '{extension}' is not supported. Please upload a file with the '.csv' extension.")
        
        # Validate ResourceFile
        resource_file_path = task_inputs.user_inputs.get('ResourceFile')
        if not resource_file_path:
            empty_attrs.append("ResourceFile")
        elif not isinstance(resource_file_path, str):
            unsupported_str_fields.append("ResourceFile")
        else:
            if not self.is_valid_url(resource_file_path):
                invalid_file_paths.append('ResourceFile')
            else:
                extension = self.get_extension(resource_file_path)
                if extension  != ".toml":
                    error_list.append(f"'ResourceFile' extension - '{extension}' is not supported. Please upload a file with the '.toml' extension.")

        if empty_attrs:
            error_list.append(f"Empty input(s): {', '.join(empty_attrs)}")
        if unsupported_date_fields:
            error_list.append(f"Unsupported date field(s): {', '.join(unsupported_date_fields)}. Supported type: Datetime")
        if unsupported_str_fields:
            error_list.append(f"Unsupported user input(s): {', '.join(unsupported_str_fields)}. Supported type: String")
        if invalid_file_paths:
            error_list.append(f"Invalid file path(s): {', '.join(invalid_file_paths)}. Valid file path: http://host:port/folder_name/file_name_with_extension")

        return error_list
    
    
    def get_extension(self, file_path):
        try:
            file_extension = os.path.splitext(file_path)[1]
            return file_extension
        except IndexError:
            return ''
    
    def is_valid_url(self, file_path):
        try:
            parsed_url = urllib.parse.urlparse(file_path)
            if not (parsed_url.scheme and parsed_url.netloc):
                return False
            return True
        except ValueError:
            return False
    

    def upload_log_file(self, errors_list):
        log_file_path, error = self.upload_file_to_minio(file_content=json.dumps(errors_list).encode('utf-8'), 
                                                         file_name=f'LogFile-{str(uuid.uuid4())}.json', content_type='application/json')
        if error:
            return {'Error': error}
        return { 'LogFile': log_file_path,}
    
    
    def check_csv_file(self, event_file_df):
        error_list = []
        try:
            # Check for required columns
            required_columns = {"EventNames", "IsRequired", "ResourceType", "UserNames"}
            if not required_columns.issubset(event_file_df.columns):
                columns_not_present = set(required_columns) - set(event_file_df.columns)
                if columns_not_present:
                    msg = ', '.join(columns_not_present)
                    error_list.append(f"Invalid 'EventFile'. {'Missing column(s): ' + msg if msg else ''}")

            # validate 'IsRequired'
            if 'IsRequired' in event_file_df.columns:
                valid_values = {"yes", "no"}        
                is_required_lower = event_file_df["IsRequired"].str.strip().str.lower()
                if not is_required_lower.isin(valid_values).all():
                    error_list.append(f"Invalid 'EventFile'. Invalid value(s) found in 'Is Required' column. Allowed values are: 'Yes', 'No'")

        except AttributeError:
            error_list.append("Invalid 'EventFile'. Please contact support for further details")
            
        return error_list
        
    
    def check_toml_file(self, toml_data):
        try:
            # By default toml table name is 'Resources'
            if not cowdictutils.is_valid_key(toml_data, 'Resources'):
                return [], [], "Table - 'Resources' is missing in 'ResourceFile'. Please provide a valid 'ResourceFile' file to proceed"

            resources = toml_data['Resources']
            include_resource_criteria = resources.get('IncludeResourceCriteria', [])
            exclude_resource_criteria = resources.get('ExcludeResourceCriteria', [])

            missing_fields = []
            if not include_resource_criteria:
                missing_fields.append('IncludeResourceCriteria')
            if not exclude_resource_criteria:
                missing_fields.append('ExcludeResourceCriteria')

            if missing_fields:
                return [], [], f"Invalid 'ResourceFile'. Missing Fields: {', '.join(missing_fields)}"

            return include_resource_criteria, exclude_resource_criteria, ''

        except KeyError as e:
            return [], [], f"Invalid 'ResourceFile'. KeyError occured: {e}. Please provide a valid TOML file."
        

    def handle_include_and_exclude_resources(self, include_resource_criteria, exclude_resource_criteria, event_services):
        try:
            
            error_list = []

            # dict that contains resource types and resources as key, value
            include_resources_with_service = {}
            exclude_resources_with_service = {}

            # Collect non-valid include and exclude resources.
            invalid_included_fields = [resource for resource in include_resource_criteria if len(resource.split("/")) != 3]
            invalid_excluded_fields = [resource for resource in exclude_resource_criteria if len(resource.split("/")) != 3]

            if invalid_included_fields:
                error_list.append(f"Invalid 'IncludeResourceCriteria': {', '.join(invalid_included_fields)}. Valid IncludeResourceCriteria format - aws/AWS::S3::Bucket/resource_names")
            if invalid_excluded_fields:
                error_list.append(f"Invalid 'ExcludeResourceCriteria': {', '.join(invalid_excluded_fields)}. Valid ExcludeResourceCriteria format - aws/AWS::S3::Bucket/resource_names")
            
            if error_list:
                return {}, {}, error_list

            # Collect non-aws resources. Invalid resource structure -  if the resource does not start with 'aws'.
            invalid_include_resource_structure = []
            # If no resources mentioned in include resource criteria
            no_resources_included = []

            for resource in include_resource_criteria:
                # aws/AWS::S3::Bucket/* - split by '/' fetch resource
                split_res = resource.split("/")
                if len(split_res) == 3:
                    if split_res[0].strip() != "aws":
                        invalid_include_resource_structure.append(resource)
                        continue
                    if not split_res[2]:
                        no_resources_included.append(resource)
                # update the dict 
                if not split_res[1] in include_resources_with_service:
                    include_resources_with_service[split_res[1]] = [split_res[2]]
                else:
                    include_resources_with_service[split_res[1]].append(split_res[2])
            
            if invalid_include_resource_structure:
                error_list.append(f"Invalid 'IncludeResourceCriteria' format: {', '.join(invalid_include_resource_structure)}. Valid IncludeResourceCriteria should start with 'aws'. Valid IncludeResourceCriteria format - aws/AWS::S3::Bucket/resource_names")
            
            if no_resources_included:
                error_list.append(f"Invalid 'IncludeResourceCriteria': {', '.join(no_resources_included)}. Atleast one resource should be included. Sample to include all resources - aws/AWS::S3::Bucket/*")
            
            # remove duplicate include resource names 
            if include_resources_with_service:
                for key, value in include_resources_with_service.items():
                    include_resources_with_service[key] = list(set(value))

            # Collect non-aws resources. Invalid resource structure -  if the resource does not start with 'aws'.
            invalid_exclude_resource_structure = []
            # If all resources mentioned in exclude criteria
            all_resources_exluded = []
    
            for resource in exclude_resource_criteria:
                # aws/AWS::S3::Bucket/* - split by '/' fetch resource
                split_res = resource.split("/")
                if len(split_res) == 3:
                    if split_res[0].strip() != "aws":
                        invalid_exclude_resource_structure.append(resource)
                        continue
                if split_res[2].strip() == '*':
                    all_resources_exluded.append(resource)
                # update the dict 
                if not split_res[1] in exclude_resources_with_service:
                    exclude_resources_with_service[split_res[1]] = [split_res[2]]
                else:
                    exclude_resources_with_service[split_res[1]].append(split_res[2])
            
            if invalid_exclude_resource_structure:
                error_list.append(f"Invalid 'ExcludeResourceCriteria' format: {', '.join(invalid_exclude_resource_structure)}. Valid ExcludeResourceCriteria should start with 'aws'. Valid ExcludeResourceCriteria format - aws/AWS::S3::Bucket/resource_names")
            
            if all_resources_exluded:
                error_list.append(f"Invalid 'ExcludeResourceCriteria': {', '.join(all_resources_exluded)}. At least one resource must be included. Not all resources can be excluded.")
            
            # remove duplicate exclude resource names 
            if invalid_exclude_resource_structure:
                for key, value in invalid_exclude_resource_structure.items():
                    invalid_exclude_resource_structure[key] = list(set(value))
            
            # check all include criteria services present in event services
            include_criteria_services = []
            include_criteria_services_not_present_in_event_services = []
            if include_resources_with_service:
               include_criteria_services = [service for service in include_resources_with_service.keys()]
               for service in include_criteria_services:
                   if not service in event_services:
                       include_criteria_services_not_present_in_event_services.append(service)
            if include_criteria_services_not_present_in_event_services:
                error_list.append(f"The following resource type(s) are not present in the 'EventFile' but exist in the 'ResourceFile' - 'IncludeResourceCriteria': {', '.join(include_criteria_services_not_present_in_event_services)}")

            # check all event services present in include criteria services
            event_services_not_present_in_include_criteria_services = []
            if include_criteria_services:
                for service in event_services:
                    if not service in include_criteria_services:
                        event_services_not_present_in_include_criteria_services.append(service)
            if event_services_not_present_in_include_criteria_services:
                error_list.append(f"The following resource type(s) are not present in the 'ResourceFile' - 'IncludeResourceCriteria' but exist in the 'EventFile': {', '.join(event_services_not_present_in_include_criteria_services)}")
            
            # check all exclude criteria services present in event services
            exclude_criteria_services = []
            exclude_criteria_services_not_present_in_event_services = []
            if exclude_resources_with_service:
               exclude_criteria_services = [service for service in exclude_resources_with_service.keys()]
               for service in exclude_criteria_services:
                   if not service in event_services:
                       exclude_criteria_services_not_present_in_event_services.append(service)
            if exclude_criteria_services_not_present_in_event_services:
                error_list.append(f"The following service(s) are not present in the 'EventFile' but exist in the 'ResourceFile' - 'ExcludeResourceCriteria': {', '.join(exclude_criteria_services_not_present_in_event_services)}")
            
            # check all event services present in exclude criteria services
            event_services_not_present_in_exclude_criteria_services = []
            if exclude_criteria_services:
                for service in event_services:
                    if not service in exclude_criteria_services:
                        event_services_not_present_in_exclude_criteria_services.append(service)
            if event_services_not_present_in_exclude_criteria_services:
                error_list.append(f"The following service(s) are not present in the 'ResourceFile' - 'ExcludeResourceCriteria' but exist in the 'EventFile': {', '.join(event_services_not_present_in_exclude_criteria_services)}")
            
            # check if resource name is included in both included and excluded criteria
            resource_present_in_both_include_and_exclude_criteria = []
            if include_resources_with_service and exclude_resources_with_service:
                for service in include_criteria_services:
                    include_resources = include_resources_with_service[service]
                    if not service in exclude_resources_with_service:
                        continue
                    exclude_resources = exclude_resources_with_service[service]
                    for resource in include_resources:
                        if resource in exclude_resources:
                            resource_present_in_both_include_and_exclude_criteria.append(resource)  

            if "*" in  resource_present_in_both_include_and_exclude_criteria:
                resource_present_in_both_include_and_exclude_criteria.remove("*")
            if resource_present_in_both_include_and_exclude_criteria:
                error_list.append(f"The following resource name(s) present in both 'IncludeResourceCriteria' and 'ExcludeResourceCriteria': {', '.join(resource_present_in_both_include_and_exclude_criteria)}.")          

            return include_resources_with_service, exclude_resources_with_service, error_list

        except (KeyError, AttributeError) as e:
            return {}, {}, [f'Exception occured while processing toml data. {str(e)}. Please contact support for further details']
        

    def get_time_stamp(self, req, field_name):
        if cowdictutils.is_valid_key(req, field_name):
            value = req[field_name]
            if isinstance(value, str):
                try:
                    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ')
                except ValueError:
                    return 'N/A'
            elif isinstance(value, datetime):
                return value.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return 'N/A'
    
    def get_url_service(self, resource):
        resource_parts = [resource_part.capitalize() for resource_part in resource.split("::") if resource_part]
        return "".join(resource_parts)
    
    
    # Method will generate ARN for resource. Handling different cases based on resource. 
    # More resources will in added in future
    def get_resource_arn(self, service='', region='', account_id='', resource_id='', resource_type=''):
        try:
            if "::" in service:
                split_parts = service.split("::", 3)
            else:
                return '', f'Invalid Service - {service}. Failed to generate ARN'
            if service == "AWS::S3::Bucket":
                return f"arn:aws:{split_parts[1]}:::{resource_id}", ''
            elif service == "AWS::KMS::Key" or service == "AWS::CloudFormation::Stack":
                return resource_id, ''
            elif service == "AWS::EKS::Nodegroup":
                return '', "N/A"
            else:
                return f"arn:aws:{split_parts[1]}:{region}:{account_id}:{split_parts[2]}/{resource_id}", ''
                
        except (KeyError, ValueError, IndexError) as e:
            return '', f"Failed to generate ARN for resource '{resource_id}'. Reason: {str(e)}. Please contact support for further details."

    
    def is_account_req_for_arn(self, resource_type):
        # The following resource types require an account in their ARN. More resource types will be added in the future
        resources_types = ["AWS::IAM::User", "AWS::EC2::Subnet", "AWS::EC2::Instance", "AWS::KMS::Key", "AWS::CloudFormation::Stack", "AWS::EKS::Nodegroup"]
        if resource_type in resources_types:
            return True
        return False   
    
    def add_key_in_list(self, error_list: list):
        unique_list = list(set(error_list))
        updated_list = []
        for err in unique_list:
             updated_list.append({'Error': err})
        return updated_list