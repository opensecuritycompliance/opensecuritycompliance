
from typing import overload
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from appconnections.kubernetes import kubernetes
from compliancecowcards.utils import cowdictutils
import json
import uuid
import pandas as pd


class Task(cards.AbstractTask):

    def execute(self) -> dict:

        error_list = []

        error_list = self.validate()
        if error_list:
            return self.upload_log_file(self.add_key_in_list(error_list))

        # Get the required include and exclude resources 
        include_clus_list, exclude_clus_list, include_pv_list, exclude_pv_list, error_list = self.get_include_and_exclude()
        if error_list:
            return self.upload_log_file(self.add_key_in_list(error_list))

        kubernetes_connector = kubernetes.Kubernetes(
            app_url=self.task_inputs.user_object.app.application_url,
            user_defined_credentials=kubernetes.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials
            )
        )

        # cluster map that contains cluster and context
        cluster_map, include_error_list, invalid_clusters = kubernetes_connector.get_include_cluster(include_clus_list)
        if include_error_list:
            error_list.extend(include_error_list)

        err_msg = ''
        # Handle error message for invalid clusters
        for invalid_cluster in invalid_clusters:
            if err_msg:
                err_msg += f". \nCluster '{invalid_cluster}' does not exist"
            else:
                err_msg = f"Cluster '{invalid_cluster}' does not exist"
        if not cluster_map and invalid_clusters:
            error_list.append(err_msg)

        if not cluster_map and include_error_list:
            return self.upload_log_file(self.add_key_in_list(error_list))

        # Fetch K8s Persistent volume detials
        pv_list, pv_error_list = kubernetes_connector.list_pvs(cluster_map)
        if pv_error_list:
            error_list.extend(pv_error_list)
        
        if not pv_list and pv_error_list:
            return self.upload_log_file(self.add_key_in_list(error_list))
        
        include_pv_map = {}

        if cluster_map and include_pv_list:
            for key in cluster_map:
                pv_map = {}
                # Update the value to False track the non valid resources
                for pv in include_pv_list:
                    pv_map[pv] = False
                # Assign pv map for each cluster
                include_pv_map[key] = pv_map
                
        
        std_pv_list = []

        for pv in pv_list:
            
            try:
                metadata = pv.get('metadata', {})
                spec = pv.get('spec', {})
                resource_name = metadata.get('name', '')
                cluster_name = pv.get('ClusterName', '')

                if not resource_name:
                    continue
                if cluster_name in exclude_clus_list and '*' in exclude_pv_list:
                    continue
                if cluster_name in exclude_clus_list and resource_name in exclude_pv_list:
                    continue
                if "*" in exclude_clus_list and resource_name in exclude_pv_list:
                    continue
                if cluster_name in include_clus_list and not '*' in include_pv_list and not resource_name in include_pv_list:
                    continue
                if cluster_name in include_pv_map:
                    if resource_name in include_pv_map[cluster_name]:
                        include_pv_map[cluster_name][resource_name] = True
                elif '*' not in include_pv_map:
                    continue

                if '*' in include_pv_list or resource_name in include_pv_list:
                    data = {
                        "System": "kubernetes",
                        "Source": "compliancecow",
                        "ResourceID": metadata.get('uid', ''),
                        "ResourceName": resource_name,
                        "ResourceType": "PersistentVolume",
                        "Version": metadata.get('resourceVersion', ''),
                        "CreatedDateTime": metadata.get('creationTimestamp', ''),
                        "Storage": spec.get('capacity', {}).get('storage', ''),
                        "ClaimName": spec.get('claimRef', {}).get('name', ''),
                        "ClaimNameSpace": spec.get('claimRef', {}).get('namespace', ''),
                        "ClaimID": spec.get('claimRef', {}).get('uid', ''),
                        "AccessModes": spec.get('accessModes', []),
                        "VolumeHandle": spec.get('csi', {}).get('volumeHandle', ''),
                        "ClusterName": cluster_name,
                    }
                    std_pv_list.append(data)

            except KeyError as e:
                return self.upload_log_file([{'Error' : f'Failed to generate KubernetesPVList. KeyError exception occurred. Invalid key: {str(e)}'}])

         
        if not "*" in include_pv_list:
            for cluster in include_pv_map:
                pv_map = include_pv_map[cluster]
                for pv in pv_map:
                    if not pv_map[pv]:
                        if err_msg:
                            err_msg += f". \nPV '{pv}' does not exist in cluster '{cluster}'"
                        else:
                            err_msg += f"PV '{pv}' does not exist in cluster '{cluster}'"

        if err_msg:
            error_list.append(err_msg)

        response = {}
        
        if std_pv_list:
            file_path, error = self.upload_df_as_parquet_file_to_minio(
             df=pd.json_normalize(std_pv_list),
             file_name=f"KubernetesPVList-{str(uuid.uuid4())}")
            if error:
                error_list.append(f"An error occurred while uplaoding 'KubernetesPVList'. {error}")
            else:
                response['KubernetesPVList'] = file_path

        
        if error_list:
            result =  self.upload_log_file(self.add_key_in_list(error_list))
            if cowdictutils.is_valid_key(result, 'Error'):
                return result
            response['KubernetesPVListLogFile'] = result['KubernetesPVListLogFile']

        return response
    
    def validate(self):
        task_inputs = self.task_inputs
        if not task_inputs:
            return ['Task input is missing']

        user_object = task_inputs.user_object
        if not user_object or not user_object.app or not user_object.app.user_defined_credentials:
            return ['User defined credential is missing']

        user_defined_credentials = user_object.app.user_defined_credentials
        if not cowdictutils.is_valid_key(user_defined_credentials, 'Jumphost'):
            return ['Jumphost credential is missing']

        # To track common error messages
        error_list = []
        invalid_types = []

        include_criteria = task_inputs.user_inputs.get('IncludeCriteria')
        exclude_criteria = task_inputs.user_inputs.get('ExcludeCriteria')

        self.validate_criteria(include_criteria, 'IncludeCriteria', invalid_types, error_list)
        if exclude_criteria:
            self.validate_criteria(exclude_criteria, 'ExcludeCriteria', invalid_types, error_list)
        
        if invalid_types:
            error_list.append(f"The following input types are not supported: {', '.join(invalid_types)}. Supported type - String")

        if not task_inputs.user_object.app.application_url:
            error_list.append("Application URL is empty")

        jump_host_credentials = user_defined_credentials.get('Jumphost')
        # To track Invalid jumphost credentials
        empty_attrs = []
        if not cowdictutils.is_valid_key(jump_host_credentials, 'UserID'):
            empty_attrs.append("UserID")
        if not cowdictutils.is_valid_key(jump_host_credentials, 'SshPrivateKey'):
            empty_attrs.append("SshPrivateKey")

        if empty_attrs:
            error_list.append("Invalid Jumphost Credentials: " + ", ".join(empty_attrs) + " is empty")

        return error_list
    
    def validate_criteria(self, criteria, criteria_name, invalid_types, error_list):
        if not criteria:
            error_list.append(f"Empty input: '{criteria_name}'. '{criteria_name}' format - '/cluster/cluster_names/pv/pv_names'")
            return False
        if not isinstance(criteria, str):
            invalid_types.append(criteria_name)
            return False
        if 'cluster' not in criteria or 'pv' not in criteria:
            error_list.append(f"Invalid '{criteria_name}'. '{criteria_name}' format - '/cluster/cluster_names/pv/pv_names'")
            return False
        split_parts = criteria.split("/")
        if len(split_parts) != 5:
            error_list.append(f"Invalid '{criteria_name}'. '{criteria_name}' format - '/cluster/cluster_names/pv/pv_names'")
            return False
        return True
    
    def get_include_and_exclude(self):

        error_list =[]
        include_criteria = self.task_inputs.user_inputs.get('IncludeCriteria')
        exclude_criteria = self.task_inputs.user_inputs.get('ExcludeCriteria')

        include_clusters, include_pv =  self.parse_criteria(include_criteria)
        exclude_clusters, exclude_pv =  self.parse_criteria(exclude_criteria)
        

        if '*' in exclude_clusters and '*' in exclude_pv:
            error_list.append("Invalid 'ExcludeCriteria': Not all clusters and PVs can be excluded.")
        if not include_clusters:
            error_list.append("Invalid 'IncludeCriteria'. No clusters added. At least one cluster should be added. Sample to add all clusters: /cluster/*")
        if not include_pv:
            error_list.append("Invalid 'IncludeCriteria'. No PV added. At least one PV should be added. Sample to add all PV: /pv/*")

        return include_clusters, exclude_clusters, include_pv, exclude_pv, error_list
    
    def parse_criteria(self, criteria):
        clusters = []
        pvs = []
        if criteria:
            split_parts = criteria.split("/")
            clusters = [cluster for cluster in split_parts[2].split(",") if cluster]
            pvs = [pv for pv in split_parts[4].split(",") if pv]
        return clusters, pvs

    def upload_log_file(self, errors_list):
        log_file_path, error = self.upload_file_to_minio(file_content=json.dumps(errors_list).encode('utf-8'), 
                                                         file_name=f'KubernetesPVListLogFile-{str(uuid.uuid4())}.json', content_type='application/json')
        if error:
            return {'Error': f"Error while uploading 'KubernetesPVListLogFile': {error}"}
        return {'KubernetesPVListLogFile': log_file_path}
    
    def add_key_in_list(self, error_list: list):
        unique_list = list(set(error_list))
        updated_list = []
        for err in unique_list:
             updated_list.append({'Error': err})
        return updated_list