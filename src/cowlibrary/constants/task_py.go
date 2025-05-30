package constants

const TaskPy = `
{{task_level_comments}}
from typing import overload
from compliancecowcards.structs import cards
{{replace_with_imports}}

logger = cards.Logger() # Initializes a Logger instance to log data, use logger.log_data(dict) to log a data

class Task(cards.AbstractTask):

    def execute(self) -> dict:

        # The following code allows you to access the input values from the YAML configuration file you provided.
        # 'user_inputs' is a dictionary containing these values.
        #
        # self.task_inputs.user_inputs.get("BucketName")

        # You can instantiate the application (selected during rule initialization) using the following approach.
        #
        # app = {{APPLICATION_PACKAGE_NAME}}.{{APPLICATION_STRUCT_NAME}}(
        #     app_url=self.task_inputs.user_object.app.application_url,
        #     app_port=self.task_inputs.user_object.app.application_port,
        #     user_defined_credentials={{APPLICATION_PACKAGE_NAME}}.UserDefinedCredentials.from_dict(
        #         self.task_inputs.user_object.app.user_defined_credentials)
        # )
        {{VALIDATION_METHOD}}

        # You can upload files to Minio by following this approach.
        # file_content: bytes
        # file_name: string
        # content_type: file formats.
        #
        # file_url, error = self.upload_file_to_minio(file_content=file_content, file_name=file_name, content_type=content_type)

        # You can download files from Minio by following this approach.
        # file_url: str
        #
        # file_bytes, error = self.download_file_from_minio(file_url=file_url)

        # TODO : write your logics here

        # PLACEHOLDER CODE #

        {{code_level_comments}}

        response = {
            "ComplianceStatus_": "NON_COMPLIANT", # The possible values for the 'Status' field should be one of the following: 'COMPLIANT' 'NON_COMPLIANT,' or 'NOT_DETERMINED.'
            "CompliancePCT_": 0,
            # Any other key:value pair that you may want to return as output
        }

        return response

{{replace_methods}}

`

const TaskHelperPy = `# This file is autogenerated. Please do not modify
import importlib
import os
import inspect
from compliancecowcards.structs import cards, cowvo
from compliancecowcards.utils import cowconstants
import json
import yaml
import uuid
from datetime import date
import traceback

TASK_OUTPUT_FILE = "task_output.json"
INPUTS_YAML_FILE = "inputs.yaml"
TASK_INPUT_JSON = "task_input.json"
LOGS_TXT_FILE = "logs.txt"

class DateEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, date):
            return obj.isoformat()
        return super().default(obj)

is_task_executed = False
dir_path = os.path.dirname(os.path.realpath(__file__))
for py_module in list(filter(lambda x: x.endswith(".py") and x != inspect.getfile(inspect.currentframe()) and x != 'autogenerated_main.py' and not x.startswith('.'), os.listdir(path=dir_path))):
    filename, file_extension = os.path.splitext(
        os.path.basename(py_module))

    if is_task_executed:
        break

    module_type = importlib.import_module(filename)
    for name, obj in inspect.getmembers(module_type):
        if inspect.isclass(obj):
            if obj != cards.AbstractTask and issubclass(obj, cards.AbstractTask):
                data = None

                try:
                    if os.path.exists(INPUTS_YAML_FILE):
                        # Open and read the YAML file
                        with open(INPUTS_YAML_FILE, 'r') as yaml_file:
                            data = yaml.load(
                                yaml_file, Loader=yaml.FullLoader)

                    elif os.path.exists(TASK_INPUT_JSON):
                        with open(TASK_INPUT_JSON) as f:
                            data = json.loads(f.read())

                    data = json.loads(os.path.expandvars(
                        json.dumps(data, cls=DateEncoder)))
                            
                    cl = obj()
                    data = cowvo.task_inputs_from_dict(data)

                    if not data.system_objects:
                        try:
                            default_system_objects = json.loads(os.path.expandvars(
                                json.dumps(cowconstants.DefaultSystemObjects)))
                            data.system_objects = cowvo.from_list(
                                cowvo.ObjectTemplate.from_dict, default_system_objects)
                            data.meta_data = cowvo.MetaDataTemplate(str(uuid.uuid4()), str(
                                uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4()))
                        except Exception:
                            pass

                    cl.task_inputs = data
                    output = cl.execute()
                    if isinstance(output, dict) and bool(output):
                        with open(TASK_OUTPUT_FILE, "w") as f:
                            f.write(json.dumps({"Outputs": output}))
                    else:
                        with open(TASK_OUTPUT_FILE, "w") as f:
                            f.write(json.dumps({"error": "not able to retrieve the outputs from the task"}))
                    is_task_executed = True
                    break
                except Exception as error:
                    with open(LOGS_TXT_FILE, "w") as file:
                        file.write(traceback.format_exc())
                    error_message = {"error": "Please review the stack trace in the logs.txt file within the task."}
                    with open(TASK_OUTPUT_FILE, "w") as file:
                        json.dump(error_message, file)
                    raise
`

const SQLRule_Task = `# This file is autogenerated. Please do not modify
from compliancecowcards.structs import cards, cowvo
from compliancecowcards.utils import cowfilestoreutils
from cowmethods.util import datahandler, cowdictutils
import pandas as pd
import yaml
import json
from unicodedata import numeric
import os
import minio
import base64
import io
import pyarrow.parquet as pq
import pyarrow as pa
import sqlalchemy


class Task(cards.AbstractTask):
    def execute(self):
        sql_rule_data, source_type = yaml.safe_load(
            open("sqlrule.yaml")), None
        if (cowdictutils.is_valid_key(sql_rule_data, "spec") and cowdictutils.is_valid_key(sql_rule_data["spec"], "sqldatasource") and
                cowdictutils.is_valid_key(sql_rule_data["spec"]["sqldatasource"], "sourcetype")):

            source_type = sql_rule_data["spec"]["sqldatasource"]['sourcetype']

        if source_type is None:
            if error:
                raise cowvo.CowException(
                    "source type cannot be empty")

        task_outputs = cowvo.TaskOutputs(dict())
        task_outputs.outputs = dict()

        connector_engine, error = datahandler.get_sql_alchemy_connector_helper(
            sql_rule_data, self.task_inputs)
        if error:
            raise cowvo.CowException(json.dumps(error))

        self.process_input_data(sql_rule_data, connector_engine)

        executed_results, error = execute_sql_statements(
            sql_rule_data, connector_engine, source_type)
        if error:
            raise cowvo.CowException(json.dumps(error))

        connector_engine.dispose()

        files = []

        compliance_status, compliance_pct = None, None
        if cowdictutils.is_valid_key(sql_rule_data['spec'], "outputs"):

            if cowdictutils.is_valid_key(sql_rule_data['spec']['outputs'], 'compliancestatus'):
                compliance_status = sql_rule_data['spec']['outputs']['compliancestatus']
            if cowdictutils.is_valid_key(sql_rule_data['spec']['outputs'], 'compliancepct'):
                compliance_pct = sql_rule_data['spec']['outputs']['compliancepct']

            if executed_results and bool(executed_results):

                if cowdictutils.is_valid_array(sql_rule_data['spec']['outputs'], "files"):
                    for file in sql_rule_data['spec']['outputs']['files']:
                        if (cowdictutils.is_valid_key(file, "name") and cowdictutils.is_valid_key(file, "shortname") and file["shortname"] in executed_results):

                            file_df = executed_results[file["shortname"]]
                            if isinstance(file_df, pd.DataFrame) and not file_df.empty:
                                temp_dict = dict()
                                temp_dict[file["shortname"]] = file_df.to_dict(
                                    orient='records')
                                if isinstance(compliance_pct, str) and compliance_pct.startswith(file["shortname"]+"."):
                                    data, error = datahandler.apply_jmespath_filter(
                                        temp_dict, compliance_pct)
                                    if error is None:
                                        raise cowvo.CowException(
                                            json.dumps(error))
                                    if data:
                                        if isinstance(data, str) and data.isnumeric():
                                            compliance_pct = int(data)
                                        elif isinstance(data, numeric):
                                            compliance_pct = data

                                if isinstance(compliance_status, str) and compliance_status.startswith(file["shortname"]+"."):
                                    data, error = datahandler.apply_jmespath_filter(
                                        temp_dict, compliance_status)
                                    if error is None:
                                        raise cowvo.CowException(
                                            json.dumps(error))
                                    if data:
                                        if isinstance(data, str) and data in ['Compliance', 'Non Compliance', 'Not Determined']:
                                            compliance_status = data

                                file_data = file_df.to_json(
                                    orient='records', default_handler=str)
                                format = "json"
                                if cowdictutils.is_valid_key(file, "format"):
                                    if file["format"] == "ndjson":
                                        format = "ndjson"
                                        file_data = file_df.to_json(
                                            orient='records', default_handler=str, lines=True)
                                        # .encode('utf-8')
                                    elif file["format"] == "csv":
                                        format = "csv"
                                        file_data = file_df.to_csv(
                                            index=False)
                                        # .encode('utf-8')

                                files.append(
                                    {"filename": file["shortname"]+"."+format, "filedata": file_data, "format": format})

        if compliance_pct and not compliance_status:
            compliance_status = "Not Determined"
            if compliance_pct > 0 and compliance_pct <= 100:
                if compliance_pct > 0 and compliance_pct < 100:
                    compliance_status = "Non Compliance"
                elif compliance_pct == 100:
                    compliance_status = "Compliance"

        if compliance_status and not compliance_pct:
            compliance_pct = 0
            if compliance_status == 'Compliance':
                compliance_pct = 100

        if not compliance_pct:
            compliance_pct = 0
        if not compliance_status:
            compliance_status = "Not Determined"

        if bool(files):
            for file in files:
                if cowdictutils.is_valid_key(file, "filename") and cowdictutils.is_valid_key(file, "filedata"):
                    format = 'json'
                    if cowdictutils.is_valid_key(file, "format"):
                        format = file['format']
                    file_hash, file_name, error = self.upload_file(
                        file_name=file['filename'], file_content=file['filedata'], content_type=format)

                    filename, file_extension = os.path.splitext(
                        os.path.basename(file['filename']))
                    task_outputs.outputs[filename] = file_name

        task_outputs.outputs['ComplianceStatus_'] = compliance_status
        task_outputs.outputs['CompliancePCT_'] = compliance_pct

        return task_outputs.outputs

    def process_input_data(self, sql_rule_data: dict, connector_engine):
        if (cowdictutils.is_valid_key(sql_rule_data, "spec") and cowdictutils.is_valid_key(sql_rule_data["spec"], "sqldatasource") and
                cowdictutils.is_valid_key(sql_rule_data["spec"]["sqldatasource"], "sourcetype")):

            source_type = sql_rule_data["spec"]["sqldatasource"]['sourcetype']

            if source_type in ['api', 'db']:
                if source_type == 'api':
                    if cowdictutils.is_valid_key(sql_rule_data["spec"]["sqldatasource"], "appselector"):
                        app_selector = sql_rule_data["spec"]["sqldatasource"]['appselector'].split(
                            ":")

                        if app_selector:
                            app, tag = None, None
                            if len(app_selector) > 1:
                                app, tag = app_selector[0], app_selector[1]
                            else:
                                app = app_selector[0]

                            app_object = cowfilestoreutils.get_system_object(
                                self.task_inputs, app, tag)

                            url, method, header, query, body = app_object.app.application_url, "GET", None, None, None
                            if app_object.credentials:
                                credentials = app_object.credentials[0]
                                if isinstance(credentials.other_cred_info, dict):
                                    if cowdictutils.is_valid_key(credentials.other_cred_info, "method"):
                                        method = credentials.other_cred_info['method']
                                    if cowdictutils.is_valid_key(credentials.other_cred_info, "header"):
                                        header = credentials.other_cred_info['header']
                                    if cowdictutils.is_valid_key(credentials.other_cred_info, "query"):
                                        query = credentials.other_cred_info['query']
                                    if cowdictutils.is_valid_key(credentials.other_cred_info, "body"):
                                        body = credentials.other_cred_info['body']

                            response_data, error = datahandler.execute_api_calls_and_get_response(
                                url, method, header, query, body)
                            if error is not None:
                                return cowvo.CowException(json.dumps(error))

                            if cowdictutils.is_valid_array(sql_rule_data["spec"]["sqldatasource"], "inputs"):

                                for input in sql_rule_data["spec"]["sqldatasource"]["inputs"]:
                                    if cowdictutils.is_valid_key(input, "shortname"):
                                        filtered_data = None
                                        if cowdictutils.is_valid_key(input, "jmespathfilter"):

                                            if not cowdictutils.is_valid_key(input, "filepath"):
                                                filtered_data, error = datahandler.apply_jmespath_filter(
                                                    response_data, input['jmespathfilter'])
                                                if error is not None:
                                                    return cowvo.CowException(json.dumps(error))
                                            elif input['filepath'].startswith("http"):
                                                filtered_data = self.get_file_data_from_path(
                                                    file_with_path=input['filepath'])
                                                if filtered_data:
                                                    filtered_data, error = datahandler.apply_jmespath_filter(
                                                        response_data, input['jmespathfilter'])
                                                    if error is not None:
                                                        return cowvo.CowException(json.dumps(error))
                                        elif cowdictutils.is_valid_key(input, "filepath") and input['filepath'].startswith("http"):
                                            filtered_data = self.get_file_data_from_path(
                                                file_with_path=input['filepath'])

                                        if filtered_data:
                                            if isinstance(filtered_data, dict):
                                                filtered_data = [filtered_data]
                                            if isinstance(filtered_data, list):
                                                filtered_data = pd.DataFrame(
                                                    filtered_data)

                                            if isinstance(filtered_data, pd.DataFrame):
                                                filtered_data.to_sql(
                                                    input["shortname"], connector_engine)

    def get_file_data_from_path(self, file_with_path):
        resp_file_name, resp_file_bytes, error = self.download_file(
            file_name=file_with_path)

        file_name_without_extension, file_extension = os.path.splitext(
            os.path.basename(resp_file_name))

        data = None
        file_extension = file_extension.replace(".", "")
        message_bytes = base64.b64decode(resp_file_bytes)

        df = pd.DataFrame()

        if file_extension == 'ndjson' or file_extension == 'json' or file_extension == 'csv':
            message = message_bytes.decode('utf-8')
            message_data = io.StringIO(message)

            if file_extension == 'ndjson':
                df = pd.read_json(message_data, lines=True,
                                  keep_default_dates=False)
            elif file_extension == 'json':
                df = pd.read_json(message_data, keep_default_dates=False)
            else:
                df = pd.read_csv(message_data)

        if file_extension == 'parquet':
            reader = pa.BufferReader(message_bytes)
            df = pq.read_table(reader).to_pandas()
        return df.to_dict(orient='records')


def execute_sql_statements(sql_rule_data, connector_engine, source_type):
    result_set, local_sql_engine = dict(), None
    if (cowdictutils.is_valid_key(sql_rule_data, "spec") and cowdictutils.is_valid_array(sql_rule_data["spec"], "sqlstatements")):
        is_local_query_present = list(filter(
            lambda x: x and cowdictutils.is_valid_key(x, "type") and x["type"] == "local", sql_rule_data["spec"]["sqlstatements"]))
        if is_local_query_present and source_type == 'db':
            local_sql_engine = sqlalchemy.create_engine(
                'sqlite://', echo=False)
        for sql_statement in sql_rule_data["spec"]["sqlstatements"]:
            if cowdictutils.is_valid_key(sql_statement, "shortname") and cowdictutils.is_valid_key(sql_statement, "sqlstatement"):
                df, error = pd.DataFrame(), None
                if is_local_query_present and source_type == 'db':
                    if cowdictutils.is_valid_key(sql_statement, "type") and sql_statement["type"] == "local":
                        df, error = datahandler.execute_query(
                            local_sql_engine, sql_statement["sqlstatement"])
                    else:
                        df, error = datahandler.execute_query(
                            connector_engine, sql_statement["sqlstatement"])
                else:
                    df, error = datahandler.execute_query(
                        connector_engine, sql_statement["sqlstatement"])
                if error is not None:
                    return None, error
                result_set[sql_statement["shortname"]] = df
                if 'index' in list(df.columns):
                    df.drop('index', inplace=True, axis=1)

                if isinstance(df, pd.DataFrame) and not df.empty:
                    df = pd.DataFrame(json.loads(df.to_json(
                        orient="records", default_handler=str)))

                    if is_local_query_present and source_type == 'db' and local_sql_engine:
                        df.to_sql(
                            sql_statement["shortname"], local_sql_engine, index=False, if_exists='append')
                    else:
                        df.to_sql(sql_statement["shortname"], connector_engine)

        if is_local_query_present and source_type == 'db':
            local_sql_engine.dispose()

    return result_set, None

`
