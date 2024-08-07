import io
import json
import os
import uuid
from minio import Minio
from compliancecowcards.structs import cowvo
from compliancecowcards.utils import cowdictutils, cowstorageserviceutils
import hashlib
from urllib import parse
import pandas as pd
from posixpath import join as urljoin


def get_file_content(task_inputs: cowvo.TaskInputs, minio_client: Minio, bucket_name: str, object_name: str, file_name: str) -> bytes and str and dict:

    file_content, error = None, None
    if not bucket_name and task_inputs is not None:
        url, _, _, bucket_name, err = get_minio_credentials(
            task_inputs)
        if not bucket_name:
            bucket_name = "demo"

    if object_name.startswith("http://") or object_name.startswith("https://"):
        path = parse.urlparse(object_name).path
        path = path[1:]
        path_arr = path.split("/")
        bucket_name = path_arr[0]
        object_name = "/".join(path_arr[1:])
        file_name = path_arr[len(path_arr)-1]

    found = minio_client.bucket_exists(bucket_name)
    if found:
        response = minio_client.get_object(bucket_name, object_name)
        file_content = response.data

    return file_name, file_content, error


def upload_file_with_path(task_inputs: cowvo.TaskInputs, minio_client: Minio, bucket_name: str, object_name: str, file_name: str, content_type: str = "application/json") -> str and str and dict:
    if not bucket_name:
        url, _, _, bucket_name, err = get_minio_credentials(
            task_inputs)
        if not bucket_name:
            bucket_name = "demo"
    found = minio_client.bucket_exists(bucket_name)
    if not found:
        return None, None, {'error': "Bucket doesn't exist"}

    folder_structure = get_folder_name(task_inputs)
    new_object_name = folder_structure+"/"+object_name

    tag = minio_client.fput_object(
        bucket_name, new_object_name, file_name, content_type)

    url, access_key, secret_key, bucket_name, err = get_minio_credentials(
        task_inputs)

    if "http://" not in url:
        url = "http://"+url

    file_name = url + "/" + bucket_name + "/" + new_object_name

    return file_name, folder_structure, None


def upload_file_with_content(task_inputs: cowvo.TaskInputs, minio_client: Minio, bucket_name: str, object_name: str,
                             file_name: str, file_content=None, content_type: str = "application/json") -> str and str and dict:
    url = "localhost:9000"
    error = None
    if not bucket_name:
        url, _, _, bucket_name, err = get_minio_credentials(
            task_inputs)
        if not bucket_name:
            bucket_name = "demo"

    found = minio_client.bucket_exists(bucket_name)
    if not found:
        minio_client.make_bucket(bucket_name)
        found = True

    folder_structure = None
    if found:
        folder_structure = object_name
        new_object_name = object_name

        if task_inputs is not None:
            folder_structure = get_folder_name(task_inputs)
            new_object_name = folder_structure+"/"+object_name
        elif "/" in folder_structure:
            folder_structure_arr = folder_structure.split("/")
            folder_structure = "/".join(
                folder_structure_arr[:len(folder_structure_arr)-1])

        content_length = 0
        if isinstance(file_content, pd.DataFrame):
            if new_object_name.endswith(".ndjson"):
                file_content = file_content.to_json(
                    orient='records', lines=True)
            elif new_object_name.endswith(".json"):
                file_content = file_content.to_json(
                    orient='records')
            elif new_object_name.endswith(".csv"):
                file_content = file_content.to_csv(index=False)
            else:

                f = io.BytesIO()
                file_content.to_parquet(f, index=False, engine='auto',
                                        compression='snappy')
                f.seek(0)
                file_content = f.read()

        if file_content:
            if isinstance(file_content, dict) or isinstance(file_content, list):
                file_content = json.dumps(file_content).encode("utf-8")

            if isinstance(file_content, str):
                file_content = file_content.encode("utf-8")

            if isinstance(file_content, bytes):
                content_length = len(file_content)
                file_content = io.BytesIO(file_content)

            etag = minio_client.put_object(
                bucket_name=bucket_name, object_name=new_object_name, data=file_content, length=content_length)

            if "http://" not in url:
                url = "http://"+url

            file_name = url + "/" + bucket_name + "/" + new_object_name
        else:
            error = {"error": "not a valid data"}
    else:
        error = {'error': "Bucket doesn't exist"}
    return file_name, folder_structure, error


def put_file_in_local_storage(task_inputs: cowvo.TaskInputs, file_name: str = None, file_content: bytes = None):
    folder_structure = get_folder_name(task_inputs)

    # file_hash, file_path, error = self.upload_file(
    # file_name = "sample.json", file_content = sample_data)

    #     file_name, file_content, error=self.download_file(
    # file_name = file_path)

    file_path = os.path.join(folder_structure, file_name)

    with open(file_path, "w") as f:
        f.write(str(file_content))
        f.flush()

    return folder_structure, file_path, None


def get_file_in_local_storage(task_inputs: cowvo.TaskInputs, file_path: str = None):
    file_name = os.path.basename(file_path)
    file_content = None
    with open(file_path, "r") as f:
        file_content = f.read()

    return file_name, file_content, None


def get_folder_name(task_inputs: cowvo.TaskInputs) -> str:
    return get_hash(task_inputs.meta_data.plan_execution_guid, task_inputs.meta_data.control_id, task_inputs.meta_data.rule_guid, task_inputs.meta_data.rule_task_guid)


def get_hash(*argv):
    hash_list = []
    for arg in argv:
        if arg is None:
            arg = str(uuid.uuid4())
        hash_list.append(hashlib.sha1(arg.encode()).hexdigest())
    return "/".join(hash_list)


def get_minio_client(url, access_key, secret_key) -> Minio:

    return Minio(
        url,
        access_key=access_key,
        secret_key=secret_key,
        secure=False,
    )


def get_system_object(task_inputs: cowvo.TaskInputs, app_name: str) -> cowvo.ObjectTemplate:
    if task_inputs.system_objects:
        for system_object in task_inputs.system_objects:
            if system_object.app and system_object.app.application_name == app_name:
                return system_object
    return None


def get_input_object(task_inputs: cowvo.TaskInputs, app_name: str = None, tag_name: str = None):
    if task_inputs.user_object and bool(task_inputs.user_object):
        return task_inputs.user_object
    if task_inputs.system_objects:
        return get_system_object(task_inputs, app_name)
    return None


def get_minio_client_with_inputs(task_inputs: cowvo.TaskInputs) -> Minio and dict:

    url, access_key, secret_key, _, err = get_minio_credentials(
        task_inputs)
    if err and bool(err):
        return None, err
    return get_minio_client(url, access_key, secret_key), None


def get_minio_credentials(task_inputs: cowvo.TaskInputs) -> str and str and str and str and dict:
    minio_system_obj = get_system_object(task_inputs, "minio")
    if minio_system_obj is None or not minio_system_obj.credentials or not isinstance(minio_system_obj.credentials, list):
        return None, None, None, None, {'error': 'minio credentials not found'}

    access_key, secret_key, url, bucket_name = None, None, None, None

    for credential in minio_system_obj.credentials:
        if hasattr(credential, "login_url") and isinstance(credential.login_url, str) and hasattr(credential, "other_cred_info") and isinstance(credential.other_cred_info, dict):
            url = credential.login_url
            if cowdictutils.is_valid_key(credential.other_cred_info, "MINIO_ACCESS_KEY") and cowdictutils.is_valid_key(credential.other_cred_info, "MINIO_SECRET_KEY"):
                access_key = credential.other_cred_info['MINIO_ACCESS_KEY']
                secret_key = credential.other_cred_info['MINIO_SECRET_KEY']
                bucket_name = credential.other_cred_info.get(
                    'BucketName', 'demo')
                break

    if not url or not access_key or not secret_key:
        return None, None, None, None, {'error': 'minio credentials not found'}

    return url, access_key, secret_key, bucket_name, None


def upload_file(task_inputs=None, minio_client=None, bucket_name=None, object_name=None, file_name=None, file_content=None, header=None, content_type=None) -> str and str and dict:
    """ File download can be handled by the following(persistence).

        1.  Minio
        2.  Trigger call to storage service(internal)
        3.  Local file system(tmp/ruleengine/outputs/{run_id}/{task_guid}/{file_name}) -
        No need external dependency. Instead of docker they can test it in their local, so the unit testing will be easier for them
        (Obiviously they can do it in their docker set up too.) And as of now, we're not mainitaining any history regarding run(in PolicyCow).
        Do we need to do it?.   And also it'll be used to club the rules and synthesizer in PolicyCow.
        Can we club synthesizer and rules in PolicyCow?  -   Raja suggested this. And I aggreed to this.

        The above 3 types can be identified based on the env variables

        COW_PERSISTENCE_TYPE: MINIO | LOCAL_FILE_STORE_PATH | STORAGE_SERVICE_PATH

        MINIO:
            "MINIO_ACCESS_KEY": "",
            "MINIO_SECRET_KEY": "",
            "MINIO_HOST":"",
            "MINIO_PORT":"",

        LOCAL_FILE_STORE_PATH:

        STORAGE_SERVICE_PATH:
            "COW_STORAGE_SERVICE_PROTOCOL":""
            "COW_STORAGE_SERVICE_HOST_NAME":""
            "COW_STORAGE_SERVICE_PORT_NUMBER":""

        Attributes
        ----------
        file_name : str
            name of the file name to be upload
        file_content : bytes
            file content
        minio_client : minio.Minio
            you can pass minio client(based on the persistence u chose).
        bucket_name : str

    """

    persistence_type = get_persistence_type()

    is_local_file_system, is_minio, is_storage = False, False, True

    file_hash, file_path, error = None, None,  None

    is_policy_cow_flow = False
    is_policy_cow_flow = os.getenv("IS_POLICY_COW_FLOW", None)
    if is_policy_cow_flow and is_policy_cow_flow == "true":
        is_policy_cow_flow = True

    is_valid_content=False

    if isinstance(file_content, pd.DataFrame):
        if not file_content.empty:
            is_valid_content = True
    elif file_content:
        is_valid_content = True


    if (persistence_type == "minio" or is_policy_cow_flow) and is_valid_content:

        if is_policy_cow_flow and minio_client is None:
            minio_url = "%s:%s" % (
                os.getenv("MINIO_HOST_NAME", "cowstorage"),
                os.getenv("MINIO_PORT_NUMBER", "9000"))

            minio_client = Minio(
                minio_url,
                access_key=os.getenv("MINIO_ROOT_USER"),
                secret_key=os.getenv("MINIO_ROOT_PASSWORD"),
                secure=False,
            )

        if minio_client is None:
            minio_client, error = get_minio_client_with_inputs(
                task_inputs)
            if error and bool(error):
                return file_hash, file_url, error

        if minio_client:
            # try:
            # file_url = bucket_name+"/"+object_name
            if object_name is None:
                object_name = file_name
            # file_url = object_name

            file_url, file_hash, error = upload_file_with_content(
                task_inputs=task_inputs, minio_client=minio_client, bucket_name=bucket_name, object_name=object_name,
                file_name=file_name, file_content=file_content, content_type=content_type)
            return file_hash, file_url, None
            # except Exception as err:
            #     print("err :", err)
            #     return file_hash, file_url, {"error": "cannot download the file"}

    elif persistence_type == "storage":
        """We'll consider this as a internal process - means the process is in our system - We'll use storage service"""
        file_resp = cowstorageserviceutils.savefile(
            bucket_name, file_name, file_content, header)
        if not object_name:
            object_name = file_name
        file_path = bucket_name+"/"+object_name
        if cowdictutils.is_valid_key(file_resp, "error"):
            return file_hash, file_path, file_resp

        url_hash_resp = cowstorageserviceutils.getfilehash(
            file_path, header)
        if cowdictutils.is_valid_key(url_hash_resp, "hash"):
            file_hash = url_hash_resp["hash"]

        return file_hash, file_path, error

    else:

        return put_file_in_local_storage(task_inputs=task_inputs, file_name=file_name, file_content=file_content)

    # another elif to be added for local file system

    if not file_hash and not file_path:
        error = {"error": "cannot upload the file"}

    return file_hash, file_path, error


def download_file(task_inputs: cowvo.TaskInputs = None, minio_client=None, bucket_name=None, object_name=None, file_name=None, hash=None, header=None) -> str and bytes and dict:
    """ File download can be handled by the following(persistence).

        1.  Minio
        2.  Trigger call to storage service(internal)
        3.  Local file system(tmp/ruleengine/outputs/{run_id}/{task_guid}/{file_name}) -
        No need external dependency. Instead of docker they can test it in their local, so the unit testing will be easier for them
        (Obiviously they can do it in their docker set up too.) And as of now, we're not mainitaining any history regarding run(in PolicyCow).
        Do we need to do it?.   And also it'll be used to club the rules and synthesizer in PolicyCow.
        Can we club synthesizer and rules in PolicyCow?  -   Raja suggested this. And I aggreed to this.

        The above 3 types can be identified based on the env variables

        COW_PERSISTENCE_TYPE: MINIO | LOCAL_FILE_STORE_PATH | STORAGE_SERVICE_PATH

        MINIO:
            "MINIO_ACCESS_KEY": "",
            "MINIO_SECRET_KEY": "",
            "MINIO_HOST":"",
            "MINIO_PORT":"",

        LOCAL_FILE_STORE_PATH:

        STORAGE_SERVICE_PATH:
            "COW_STORAGE_SERVICE_PROTOCOL":""
            "COW_STORAGE_SERVICE_HOST_NAME":""
            "COW_STORAGE_SERVICE_PORT_NUMBER":""

        Attributes
        ----------
        file_name : str
            name of the file name to be upload
        file_content : bytes
            file content
        minio_client : minio.Minio
            you can pass minio client(based on the persistence u chose).
        bucket_name : str

    """

    persistence_type = get_persistence_type()

    resp_file_name, resp_file_bytes, error = None, None, None

    if persistence_type == "minio" and object_name:

        if minio_client is None:
            minio_client, error = get_minio_client_with_inputs(task_inputs)
            if error and bool(error):
                return resp_file_name, resp_file_bytes, error

        if minio_client:
            try:
                resp_file_name, resp_file_bytes, error = get_file_content(
                    task_inputs, minio_client, bucket_name, object_name, file_name)
            except:
                error = {"error": "cannot download the file"}

    elif persistence_type == "storage" and hash:
        """We'll consider this as a internal process - means the process is in our system - We'll use storage service"""
        file_resp = cowstorageserviceutils.getfile(hash, header)
        if cowdictutils.is_valid_key(file_resp, "error"):
            return resp_file_name, resp_file_bytes, file_resp

        if cowdictutils.is_valid_key(file_resp, "FileContent"):
            resp_file_bytes = file_resp["FileContent"]

        if cowdictutils.is_valid_key(file_resp, "FileName"):
            resp_file_name = file_resp["FileName"]

        return resp_file_name, resp_file_bytes, error

    else:
        return get_file_in_local_storage(task_inputs=task_inputs, file_path=file_name)

    # another elif to be added for local file system

    if not resp_file_name and not resp_file_bytes:
        error = {"error": "cannot download the file"}

    return resp_file_name, resp_file_bytes, error


def get_persistence_type():
    return os.getenv("COW_DATA_PERSISTENCE_TYPE", "file")


def add_extension_if_missing(filename, extension):
    if isinstance(filename, str) and extension and not filename.endswith(extension):
        if not extension.startswith("."):
            extension = f".{extension}"
        filename = f"{filename}{extension}"
    return filename


def get_absolute_path(minio_url: str = "localhost:9000", folder_path: str = None, file_name: str = None) -> str:
    return "http://"+minio_url+urljoin(folder_path, file_name)
