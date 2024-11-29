from typing import overload
from urllib.parse import urlparse
from compliancecowcards.structs import cards
# As per the selected app, we're importing the app package
from appconnections.privacybisonconnector import privacybisonconnector
from compliancecowcards.utils import cowdictutils
from appconnections.sshconnector import sshconnector
import json
import uuid
import pandas as pd
import re
import jsbeautifier

class Task(cards.AbstractTask):

    def execute(self) -> dict:
        response = {}
        error = self.check_inputs()
        if error:
            return self.upload_log_file([{'Error': error}])

        semgrep_credentials, error = self.get_semgrep_cli_credentials()
        if error:
           return self.upload_log_file([{'Error': error}])

        har_file_bytes, error = self.download_file_from_minio(
            file_url=self.task_inputs.user_inputs.get('HarFile'))
        if error:
           return self.upload_log_file([{'Error': f'{error}'}])

        try:
            string_data = har_file_bytes.decode('utf-8')
            self.privacybison_obj = privacybisonconnector.PrivacyBisonConnector()
            har_file_data = json.loads(string_data)
        except json.JSONDecodeError as e:
            return self.upload_log_file([{'Error': f'{e}'}])
        
        domain_name, error = self.privacybison_obj.get_company_name_from_har_file(har_file_data)
        if error:
            return self.upload_log_file([{'Error': f'{error}'}])

        js_data, ts_data = self.get_unique_url_from_har_data(har_file_data)
        if not js_data and not ts_data:
            return self.upload_log_file([{'Error': 'No JavaScript or TypeScript request URLs were found in the provided HAR file.'}])
    
        ssh_data = {
            'UserName': semgrep_credentials['UserName'],
            'SSHKey': semgrep_credentials['SSHPrivateKey']
        }
        ssh_instance = sshconnector.SSH.from_dict(ssh_data)
        
        self.ssh_connector = sshconnector.SSHConnector(
            app_url=semgrep_credentials['LoginURL'],
            app_port = self.extract_port_from_url(semgrep_credentials['LoginURL']),
            user_defined_credentials=sshconnector.UserDefinedCredentials(
                ssh_instance)
        )
        vuln_result_df, semgrep_vuln_df, error_list = self.scan_script_files_using_semgrep_cli(
            js_data, ts_data, domain_name)

        if error_list:
            log_dict = self.upload_log_file(error_list)
            if cowdictutils.is_valid_key(log_dict, 'LogFile'):
                response['LogFile'] = log_dict['LogFile']
            elif cowdictutils.is_valid_key(log_dict, 'error'):
                return log_dict

        if not vuln_result_df.empty:
            file_path, error = self.upload_output_file(
                'StdSemgrepVulsReport', vuln_result_df)
            if error:
                return {'error': error}
            response['StdSemgrepVulsReport'] = file_path

        if not semgrep_vuln_df.empty:
            file_path, error = self.upload_output_file(
                'SemgrepVulsReport', semgrep_vuln_df)
            if error:
                return {'error': error}
            response['SemgrepVulsReport'] = file_path

        return response

    def check_inputs(self):
        user_inputs = self.task_inputs.user_inputs
        if not user_inputs:
            return 'User inputs are missing.'
        if not cowdictutils.is_valid_key(user_inputs, 'HarFile'):
            return 'HarFile path is empty. Provide a valid file path.'
        return None

    def get_semgrep_cli_credentials(self):
        system_objects = self.task_inputs.system_objects

        if not system_objects:
            return None, 'System Objects are empty. Please contact admin/support to fix this issue.'

        for system_object in system_objects:
            if system_object.server and system_object.server.server_name == 'semgrep-cli':
                if system_object.credentials:
                    credentials = {
                        'LoginURL': system_object.credentials[0].login_url,
                        'UserName': system_object.credentials[0].user_id,
                        'SSHPrivateKey': system_object.credentials[0].ssh_private_key
                    }
                    return credentials, None
                else:
                    return None, 'Credentials are missing for semgrep-cli server. Please contact admin/support to fix this issue.'

        return None, 'Unable to find the semgrep-cli installed server in the system objects. Please contact admin/support to fix this issue.'

    def get_unique_url_from_har_data(self, har_file_data: dict):
        js_data = []
        ts_data = []
        js_urls_seen = []
        ts_urls_seen = []

        if 'log' in har_file_data and 'entries' in har_file_data['log']:
            entries = har_file_data['log']['entries']
            for entry in entries:
                request = entry.get('request', {})
                response = entry.get('response', {}).get('content', {})
                if 'url' in request and 'text' in response and response['text']:
                    mime_type = response.get('mimeType', '')
                    url = request['url']
                    text = response['text']
                    if url.endswith(".json"):
                        continue
                    elif mime_type in ('application/javascript','application/x-javascript','text/javascript') and url not in js_urls_seen:
                        js_data.append({'URL': url, 'Text': text})
                        js_urls_seen.append(url)
                    elif mime_type in ('application/typescript','application/x-typescript','text/typescript') and url not in ts_urls_seen:
                        ts_data.append({'URL': url, 'Text': text})
                        ts_urls_seen.append(url)

        return js_data, ts_data

    def scan_script_files_using_semgrep_cli(self, js_data: dict, ts_data: dict, domain_name: str):
        vuln_result_list = []
        error_list = []
        data_list = []
        semgrep_vuln_df = pd.DataFrame()
        

        self.scan_and_process_data(
            js_data, domain_name, 'JS', vuln_result_list, data_list, error_list)

        self.scan_and_process_data(
            ts_data, domain_name, 'TS', vuln_result_list, data_list, error_list)
        if data_list:
            semgrep_vuln_df = pd.DataFrame(data_list)
            semgrep_vuln_df = semgrep_vuln_df.astype(str)

        return pd.DataFrame(vuln_result_list), semgrep_vuln_df, error_list

    def scan_and_process_data(self, file_info: dict, domain_name: str, file_extension: str, vuln_result_list: list, data_list: list, error_list: list):
        meta_data = self.task_inputs.meta_data

        resource_type = ''
        if file_extension == 'JS':
            resource_type = 'JavaScript'
        elif file_extension == 'TS':
            resource_type = 'TypeScript'

        for value in file_info:
            beautified_code = jsbeautifier.beautify(value['Text'])
            file_path = f'Semgrep{file_extension}File-{meta_data.plan_execution_guid}.{file_extension.lower()}'
            file_status, error = self.ssh_connector.write_to_remote_file(
                file_path, beautified_code)
            if error:
                error_list.append(
                    {'Error': f"Resource '{value['URL']}' encountered an error: {error}"})
                continue

            output, error, exit_status = self.ssh_connector.exec_command(
                f'semgrep --config "p/{resource_type.lower()}" --json {file_path}')

            self.ssh_connector.remove_remote_file(file_path)
            if error:
                error_list.append(
                    {'Error': f"Resource '{value['URL']}' encountered an error: {error}"})
                continue

            json_pattern = re.compile(
                r'\{"errors":.*?"version":\s*".*?"\}', re.DOTALL)
            matches = json_pattern.findall(output)
            if matches:
                output = matches[0]

            try:
                data = json.loads(output)
            except json.JSONDecodeError as e:
                error_list.append(
                    {'Error': f"Resource '{value['URL']}' encountered an error: {e}"})
                continue
            except TypeError as e:
                error_list.append(
                    {'Error': f"Resource '{value['URL']}' encountered an error: {e}"})
                continue

            if cowdictutils.is_valid_array(data, 'results'):
                data_df = pd.json_normalize(data['results'])
                required_columns = ['path', 'start.line', 'end.line', 'check_id', 'extra.message', 'extra.metadata.impact', 'extra.metadata.likelihood', 'extra.severity', 'extra.metadata.owasp', 'extra.metadata.source']
                missing_columns = [col for col in required_columns if col not in data_df.columns]
                if missing_columns:
                    error_list.append({'Error': f"Resource '{value['URL']}' encountered an error: Required columns missing: {', '.join(missing_columns)}"})
                    continue
                data_df.drop(columns=['path'], inplace=True)
                data_df['url'] = value['URL']
                data_df['start.line'] = data_df['start.line'].astype(str)
                data_df['end.line'] = data_df['end.line'].astype(str)
                selected_columns = data_df[['url', 'check_id', 'end.line', 'start.line', 'extra.message', 'extra.metadata.impact', 'extra.metadata.likelihood', 'extra.severity', 'extra.metadata.owasp', 'extra.metadata.source']].rename(
                    columns={'url': 'ResourceID', 'check_id': 'SemgrepRuleName', 'end.line': 'VulnerabilityEndLine', 'start.line': 'VulnerabilityStartLine', 'extra.message': 'Message', 'extra.metadata.impact': 'Impact', 'extra.metadata.likelihood': 'Likelihood', 'extra.severity': 'Severity', 'extra.metadata.owasp': 'OWASP', 'extra.metadata.source':'SemgrepRuleURL'})
                selected_columns['System'] = domain_name
                selected_columns['Source'] = 'compliancecow'
                selected_columns['ResourceName'] = 'N/A'
                selected_columns['ResourceType'] = resource_type
                selected_columns['ResourceLocation'] = 'N/A'
                selected_columns['ResourceTags'] = 'N/A'
                selected_columns['ResourceURL'] = 'N/A'
                selected_columns['ValidationStatusCode'] = 'VULN_FOUND'
                selected_columns[
                    'ValidationStatusNotes'] = f'Vulnerabilities found in {resource_type} file scanned by Semgrep.'
                selected_columns['ComplianceStatus'] = 'NON_COMPLIANT'
                selected_columns['ComplianceStatusReason'] = f'The {resource_type} file scanned by Semgrep identifies vulnerabilities that pose potential security risks.'
                selected_columns['EvaluatedTime'] = self.privacybison_obj.get_current_datetime()
                selected_columns['UserAction'] = ""
                selected_columns['ActionStatus'] = ""
                selected_columns['ActionResponseURL'] = ""
                desired_order = ['System', 'Source', 'ResourceID', 'ResourceName', 'ResourceType', 'ResourceLocation', 'ResourceTags', 'ResourceURL', 'SemgrepRuleName', 'SemgrepRuleURL', 'Message', 'VulnerabilityStartLine', 'VulnerabilityEndLine',
                                 'Impact', 'Likelihood', 'Severity', 'OWASP', 'ValidationStatusCode', 'ValidationStatusNotes', 'ComplianceStatus', 'ComplianceStatusReason', 'EvaluatedTime', 'UserAction', 'ActionStatus', 'ActionResponseURL']
                selected_columns = selected_columns[desired_order]
                vuln_result_list.extend(selected_columns.to_dict(orient='records'))
                data_list.extend(data_df.to_dict(orient='records'))
            elif cowdictutils.is_valid_array(data, 'errors'):
                error_data_df = pd.json_normalize(data['errors'])
                error_type = error_data_df['type'].iloc[0] if 'type' in error_data_df else 'Unknown error type'
                timeout_errors = error_data_df['message'].str.contains('Timeout when running')
                if timeout_errors.any():
                    timeout_rules = error_data_df.loc[timeout_errors, 'message'].str.extract(r'running\s+(\S+)')[0].unique()[:3]
                    timeout_message = f"Timeout when running {', '.join(timeout_rules)} occurred while scanning {resource_type} file."
                else:
                    timeout_message = "An unknown error occurred."

                error_list.append({'Error': f"Resource '{value['URL']}' encountered a Semgrep error: {timeout_message} ({error_type})"})
            else:
                data_dict = {
                    'System': domain_name,
                    'Source': 'compliancecow',
                    'ResourceID': value['URL'],
                    'ResourceName': 'N/A',
                    'ResourceType': resource_type,
                    'ResourceLocation': 'N/A',
                    'ResourceTags': 'N/A',
                    'ResourceURL': 'N/A',
                    'SemgrepRuleName': 'N/A',
                    'SemgrepRuleURL': 'N/A',
                    'Message': 'N/A',
                    'VulnerabilityStartLine': 'N/A',
                    'VulnerabilityEndLine': 'N/A',
                    'Impact': 'N/A',
                    'Likelihood': 'N/A',
                    'Severity': 'N/A',
                    'OWASP': [],
                    'ValidationStatusCode': 'NO_VULN_FOUND',
                    'ValidationStatusNotes': f'No vulnerabilities found in {resource_type} file scanned by Semgrep.',
                    'ComplianceStatus': 'COMPLIANT',
                    'ComplianceStatusReason': f'The {resource_type} file scanned by Semgrep adheres to coding standards and does not contain vulnerabilities, ensuring compliance with coding best practices.',
                    'EvaluatedTime': self.privacybison_obj.get_current_datetime(),
                    'UserAction': "",
                    'ActionStatus': "",
                    'ActionResponseURL': ""
                }
                vuln_result_list.append(data_dict)

        return vuln_result_list, data_list, error_list
    
    def extract_port_from_url(self, login_url):
        try:
            parsed_url = urlparse(login_url)
            if parsed_url.port:
                return parsed_url.port
            else:
                return "Port not specified in the URL"
        except ValueError as ve:
            return f"ValueError occurred: {str(ve)}"
        except AttributeError as ae:
            return f"AttributeError occurred: {str(ae)}"
        except Exception as e:
            return f"Unexpected error occurred: {str(e)}"

    def upload_log_file(self, errors_list: list):
        absolute_file_path, error = self.upload_file_to_minio(file_content=json.dumps(errors_list).encode(
            'utf-8'), file_name=f'LogFile-{str(uuid.uuid4())}.json', content_type='application/json')
        if error:
            return {'error': error}
        return {
            'LogFile': absolute_file_path
        }

    def upload_output_file(self, file_name: str, data_df: pd.DataFrame):
        absolute_file_path, error = self.upload_df_as_parquet_file_to_minio(
            data_df, file_name)
        if error:
            return None, error
        return absolute_file_path, None