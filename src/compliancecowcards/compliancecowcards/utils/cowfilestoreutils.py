import io
import json
import os
import uuid
from minio import Minio
from minio.error import S3Error
from compliancecowcards.structs import cowvo
from compliancecowcards.utils import cowdictutils, cowstorageserviceutils
import hashlib
from urllib import parse
import pandas as pd
import base64
from posixpath import join as urljoin
import time
import mimetypes

file_store_bucket_name = os.getenv("COW_STORAGE_BUCKET_NAME")
file_store_prefix = os.getenv("COW_STORAGE_FILE_PREFIX")
create_bucket = os.getenv("COW_STORAGE_CREATE_BUCKET", "true").lower() == "true"


def get_file_content(task_inputs: cowvo.TaskInputs, minio_client: Minio, bucket_name: str, object_name: str, file_name: str) -> bytes and str and dict:

    file_content, error = None, None
    if not bucket_name and task_inputs is not None:
        url, _, _, bucket_name, err = get_minio_credentials(task_inputs)
        if not bucket_name:
            bucket_name = "demo"

    if object_name.startswith("http://") or object_name.startswith("https://"):
        src_object_path = object_name
        parsed_url = parse.urlparse(object_name)
        src_path = parsed_url.path
        path = src_path[1:]
        path_arr = path.split("/")
        bucket_name = path_arr[0]
        object_name = "/".join(path_arr[1:])
        file_name = path_arr[len(path_arr) - 1]

        if is_amazon_s3_host(src_object_path):
            src_path_arr = src_path.split("/")
            if len(src_path_arr) < 4:
                return None, None, {"error": "invalid URL structure, cannot extract bucket and object"}

            bucket_name = src_path_arr[3]
            object_name = "/".join(src_path_arr[4:])

            prefix_arr = parse.parse_qs(parsed_url.query).get("prefix")
            if isinstance(prefix_arr, list) and prefix_arr:
                object_name = prefix_arr[0]

    found = minio_client.bucket_exists(bucket_name)
    if found:
        response = minio_client.get_object(bucket_name, object_name)
        file_content = response.data

    return file_name, file_content, error


def upload_file_with_path(task_inputs: cowvo.TaskInputs, minio_client: Minio, bucket_name: str, object_name: str, file_name: str, content_type: str = "application/json") -> str and str and dict:
    if not bucket_name:
        url, _, _, bucket_name, err = get_minio_credentials(task_inputs)
        if not bucket_name:
            bucket_name = "demo"

    bucket_name, prefix = get_bucket_and_prefix(bucket_name)

    found = minio_client.bucket_exists(bucket_name)
    if not found:
        return None, None, {"error": "Bucket doesn't exist"}

    folder_structure = prefix + get_folder_name(task_inputs)
    new_object_name = folder_structure + "/" + object_name

    tag = minio_client.fput_object(bucket_name, new_object_name, file_name, content_type)

    if is_amazon_s3_host(minio_client._base_url.host):
        file_name, error = build_object_url_with_host(minio_client=minio_client, bucket=bucket_name, object_name=new_object_name)
        if error:
            return None, None, error
    else:
        url, _, _, bucket_name, _ = get_minio_credentials(task_inputs)

        if "http://" not in url:
            url = "http://" + url

        file_name = url + "/" + bucket_name + "/" + new_object_name

    return file_name, folder_structure, None


def upload_file_with_content(task_inputs: cowvo.TaskInputs, minio_client: Minio, bucket_name: str, object_name: str, file_name: str, file_content=None, content_type: str = "application/json") -> str and str and dict:
    url = "localhost:9000"
    error = None
    if not bucket_name:
        url, _, _, bucket_name, err = get_minio_credentials(task_inputs)
        if not bucket_name:
            bucket_name = "demo"

    bucket_name, prefix = get_bucket_and_prefix(bucket_name)

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
            new_object_name = folder_structure + "/" + object_name
        elif "/" in folder_structure:
            folder_structure_arr = folder_structure.split("/")
            folder_structure = "/".join(folder_structure_arr[: len(folder_structure_arr) - 1])

        content_length = 0
        if isinstance(file_content, pd.DataFrame):
            if new_object_name.endswith(".ndjson"):
                file_content = file_content.to_json(orient="records", lines=True)
            elif new_object_name.endswith(".json"):
                file_content = file_content.to_json(orient="records")
            elif new_object_name.endswith(".csv"):
                file_content = file_content.to_csv(index=False)
            else:

                f = io.BytesIO()
                file_content.to_parquet(f, index=False, engine="auto", compression="snappy")
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

            new_object_name = prefix + new_object_name
            folder_structure = prefix + folder_structure

            max_retries = 3
            for attempt in range(1, max_retries + 1):
                try:
                    etag = minio_client.put_object(
                        bucket_name=bucket_name,
                        object_name=new_object_name,
                        data=file_content,
                        length=content_length,
                    )
                    break  # success — exit the retry loop
                except S3Error as e:
                    #  Retry only on IncompleteBody error:
                    # minio.error.S3Error: S3 operation failed; code: IncompleteBody, 
                    # message: You did not provide the number of bytes specified by the Content-Length HTTP header.
                    if e.code != "IncompleteBody":
                        raise

                    if attempt < max_retries:
                        wait = 2 ** (attempt - 1)   # 1s, 2s, 4s back-off
                        print(f"[MinIO] put_object attempt {attempt} failed ({e.code}). "
                              f"Retrying in {wait}s...")
                        time.sleep(wait)
                    else:
                        print(f"[MinIO] put_object failed after {max_retries} attempts: {e}")
                        raise

            if is_amazon_s3_host(minio_client._base_url.host):
                file_name, error = build_object_url_with_host(minio_client=minio_client, bucket=bucket_name, object_name=new_object_name)
            else:
                if "http://" not in url:
                    url = "http://" + url

                file_name = url + "/" + bucket_name + "/" + new_object_name
        else:
            error = {"error": "not a valid data"}
    else:
        error = {"error": "Bucket doesn't exist"}
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

    secure = False
    if is_amazon_s3_host(url):
        secure = True

    return Minio(
        url,
        access_key=access_key,
        secret_key=secret_key,
        secure=secure,
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

    url, access_key, secret_key, _, err = get_minio_credentials(task_inputs)
    if err and bool(err):
        return None, err
    return get_minio_client(url, access_key, secret_key), None


def get_minio_credentials(task_inputs: cowvo.TaskInputs) -> str and str and str and str and dict:
    minio_system_obj = get_system_object(task_inputs, "minio")
    if minio_system_obj is None or not minio_system_obj.credentials or not isinstance(minio_system_obj.credentials, list):
        return None, None, None, None, {"error": "minio credentials not found"}

    access_key, secret_key, url, bucket_name = None, None, None, None

    for credential in minio_system_obj.credentials:
        if hasattr(credential, "login_url") and isinstance(credential.login_url, str) and hasattr(credential, "other_cred_info") and isinstance(credential.other_cred_info, dict):
            url = credential.login_url
            if cowdictutils.is_valid_key(credential.other_cred_info, "MINIO_ACCESS_KEY") and cowdictutils.is_valid_key(credential.other_cred_info, "MINIO_SECRET_KEY"):
                access_key = credential.other_cred_info["MINIO_ACCESS_KEY"]
                secret_key = credential.other_cred_info["MINIO_SECRET_KEY"]
                bucket_name = credential.other_cred_info.get("BucketName", "demo")
                break

    if not url or not access_key or not secret_key:
        return None, None, None, None, {"error": "minio credentials not found"}

    return url, access_key, secret_key, bucket_name, None


def upload_file(task_inputs=None, minio_client=None, bucket_name=None, object_name=None, file_name=None, file_content=None, header=None, content_type=None) -> str and str and dict:
    """File download can be handled by the following(persistence).

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

    file_hash, file_path, error = None, None, None

    is_policy_cow_flow = False
    is_policy_cow_flow = os.getenv("IS_POLICY_COW_FLOW", None)
    if is_policy_cow_flow and is_policy_cow_flow == "true":
        is_policy_cow_flow = True

    try:
        validate_file_content(file_content)
         # If content is valid → continue
    except CCowEmptyFileContentException as e:
        # e.to_dict() returns: {"error": "File content is empty: ..."}
        return None, None, e.to_dict()  
       

    if (persistence_type == "minio" or is_policy_cow_flow):

        if is_policy_cow_flow and minio_client is None:
            minio_url = "%s:%s" % (os.getenv("MINIO_HOST_NAME", "cowstorage"), os.getenv("MINIO_PORT_NUMBER", "9000"))

            minio_login_url = os.getenv("MINIO_LOGIN_URL")
            if minio_login_url:
                minio_url = minio_login_url

            minio_client = get_minio_client(minio_url, os.getenv("MINIO_ROOT_USER"), os.getenv("MINIO_ROOT_PASSWORD"))

        if minio_client is None:
            minio_client, error = get_minio_client_with_inputs(task_inputs)
            if error and bool(error):
                return file_hash, file_url, error

        if minio_client:
            # try:
            # file_url = bucket_name+"/"+object_name
            if object_name is None:
                object_name = file_name
            # file_url = object_name

            file_url, file_hash, error = upload_file_with_content(task_inputs=task_inputs, minio_client=minio_client, bucket_name=bucket_name, object_name=object_name, file_name=file_name, file_content=file_content, content_type=content_type)
            return file_hash, file_url, None
            # except Exception as err:
            #     print("err :", err)
            #     return file_hash, file_url, {"error": "cannot download the file"}

    elif persistence_type == "storage":
        """We'll consider this as a internal process - means the process is in our system - We'll use storage service"""
        file_resp = cowstorageserviceutils.savefile(bucket_name, file_name, file_content, header)
        if not object_name:
            object_name = file_name
        file_path = bucket_name + "/" + object_name
        if cowdictutils.is_valid_key(file_resp, "error"):
            return file_hash, file_path, file_resp

        url_hash_resp = cowstorageserviceutils.getfilehash(file_path, header)
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
    """File download can be handled by the following(persistence).

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

    while True:

        is_url = object_name and (object_name.startswith("http://") or object_name.startswith("https://"))

        if persistence_type == "minio" and object_name and is_url:

            if minio_client is None:
                minio_client, error = get_minio_client_with_inputs(task_inputs)
                if error and bool(error):
                    return resp_file_name, resp_file_bytes, error

            if minio_client:
                try:
                    resp_file_name, resp_file_bytes, error = get_file_content(task_inputs, minio_client, bucket_name, object_name, file_name)
                except:
                    try:
                        assert str(object_name).startswith('http://localhost')
                        obj_file_path = str(parse.urlparse(object_name).path).lstrip('/')
                        file_hash_resp: dict[str, str] | None = cowstorageserviceutils.getfilehash(obj_file_path, header)
                        object_name = file_hash_resp.get('hash') if file_hash_resp else None
                        assert bool(object_name)
                    except:
                        return resp_file_name, resp_file_bytes, {"error": "cannot download the file"}
                    continue

        elif not is_url or (persistence_type == "storage" and hash):
            """We'll consider this as a internal process - means the process is in our system - We'll use storage service"""
            file_resp = cowstorageserviceutils.getfile(object_name, header)
            if cowdictutils.is_valid_key(file_resp, "error"):
                return resp_file_name, resp_file_bytes, file_resp

            if cowdictutils.is_valid_key(file_resp, "FileContent"):
                resp_file_bytes = base64.b64decode(file_resp["FileContent"])

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


# Custom overrides for MIME types that mimetypes doesn't recognize,
# or where it returns an extension we don't want.
CCOW_CUSTOM_EXT_MAP = {
    "application/toml": ".toml",
    "application/x-yaml": ".yaml",
    "application/x-parquet": ".parquet",
    "application/vnd.apache.parquet": ".parquet",
    "application/xml": ".xml",  # mimetypes returns .xsl for this, override it
}


def add_extension_if_missing(filename: str, extension: str) -> str:
    """
    Appends the specified file extension (or MIME type extension) to the
    filename, but only if the filename doesn't already end with it.

    You can pass either:
      - a plain extension, e.g. "pdf" or ".pdf"
      - a MIME type, e.g. "application/json"

    Example:
        add_extension_if_missing("form.json", "application/json") -> "form.json"
        add_extension_if_missing("form", "application/json")      -> "form.json"
        add_extension_if_missing("document", "pdf")                -> "document.pdf"
        add_extension_if_missing("data", "application/xml")        -> "data.xml"
    """
    if isinstance(filename, str) and extension:

        # If a MIME type was passed (contains "/"), resolve it to a real extension
        if "/" in extension:
            # Step 1: check our custom map first (known overrides/missing types)
            # Step 2: fall back to Python's built-in mimetypes module
            # Step 3: last resort, use the subtype after "/" (e.g. "foo" -> ".foo")
            extension = (
                CCOW_CUSTOM_EXT_MAP.get(extension)      # Step 1
                or mimetypes.guess_extension(extension)  # Step 2
                or f".{extension.split('/')[-1]}"        # Step 3
            )

        # ensure leading dot
        if not extension.startswith("."):
            extension = f".{extension}"

        # append only if not already present
        if not filename.lower().endswith(extension.lower()):
            filename = f"{filename}{extension}"

    return filename

def get_absolute_path(minio_url: str = "localhost:9000", folder_path: str = None, file_name: str = None) -> str:
    return "http://" + minio_url + urljoin(folder_path, file_name)


def build_object_url(minio_client, bucket, object_name):
    """Build the object URL."""
    return build_object_url_with_host(minio_client, bucket, object_name, "")


def build_object_url_with_host(minio_client: Minio = None, bucket: str = None, object_name: str = None, host: str = None):
    """Build the object URL with the host."""
    if not host:

        host = minio_client._base_url.host  # Get the host from Minio client

    is_amazon_s3 = is_amazon_s3_host(host)

    try:
        region = minio_client._get_region(bucket_name=bucket)
    except S3Error as err:
        return None, {"error": f"Error happened while getting bucket region {err}"}

    scheme = "https" if minio_client._base_url.is_https else "http"
    base_url = f"{scheme}://{host}"

    if is_amazon_s3:
        # s3_url = f"https://{region}.console.aws.amazon.com/s3/buckets/{bucket}?region={region}&prefix={object_name}"
        s3_url = f"https://{region}.console.aws.amazon.com/s3/buckets/{bucket}?prefix={object_name}"
    else:
        s3_url = f"{base_url}/{bucket}/{object_name}"

    return s3_url, None


def is_amazon_s3_host(host):
    """Check if the host is Amazon S3."""
    return "s3.amazonaws.com" in host or host.startswith("s3.") or "console.aws.amazon.com" in host


def get_bucket_and_prefix(bucket_name):
    """Get the bucket and prefix based on environment settings."""
    new_bucket_name = bucket_name
    prefix = ""

    if file_store_bucket_name:
        new_bucket_name = file_store_bucket_name
        prefix = bucket_name + "/"
        if file_store_prefix:
            prefix += file_store_prefix + "/"

    return new_bucket_name, prefix


def load_bool(value, default_value):
    """Parse boolean values from strings."""
    try:
        return value.lower() == "true"
    except Exception:
        return default_value
    
    
def parse_minio_url(file_url: str):
    """
    Parse a MinIO / S3 object URL and return (bucket_name, object_name).

    Supports:
    - http://host/bucket/path/file.ext
    - https://host/bucket/path/file.ext
    """
    if not file_url:
        return None, None

    parsed_url = parse.urlparse(file_url)
    path = parsed_url.path.lstrip("/")
    parts = path.split("/")

    if len(parts) < 2:
        return None, None

    bucket_name = parts[0]
    object_name = "/".join(parts[1:])

    if is_amazon_s3_host(parsed_url.netloc):
        if len(parts) >= 4:
            bucket_name = parts[2]
            object_name = "/".join(parts[3:])

    return bucket_name, object_name

class CCowEmptyFileContentException(Exception):
    """Custom exception for empty or invalid file content"""
    
    def __init__(self, message: str = None):
        # Store the error message and pass to parent Exception class
        super().__init__(message)
        self.message = message

    def to_dict(self) -> dict:
        # Convert exception to dictionary format for API/JSON responses
        return {
            "error": self.message,
        }

    def __str__(self):
        # Return string representation for logging and debugging
        return self.message or "File content is empty"

def validate_file_content(file_content) -> None:
    # Check if the file content is None 
    if file_content is None:
        raise CCowEmptyFileContentException(
            "File content is empty: received None value"
        )

    # Handle pandas DataFrame objects
    if isinstance(file_content, pd.DataFrame):
        # Raise an exception if the DataFrame has no rows or columns
        if file_content.empty:
            raise CCowEmptyFileContentException(
                "File content is empty: DataFrame is empty"
            )
        return

    # Handle string content
    if isinstance(file_content, str):
        # Remove whitespace and check if the string is blank
        if not file_content.strip():
            raise CCowEmptyFileContentException(
                "File content is empty: string is blank"
            )
        return

    # Handle byte content
    if isinstance(file_content, bytes):
        # Check if the byte sequence is empty
        if len(file_content) == 0:
            raise CCowEmptyFileContentException(
                "File content is empty: bytes is empty"
            )
        return

    # Handle common collection types
    if isinstance(file_content, (list, dict)):
        # Check if the collection contains any elements
        if not file_content:
            raise CCowEmptyFileContentException(
                f"File content is empty: {type(file_content).__name__} is empty"
            )
        return

    # Fallback validation for any other type:
    if not file_content:
        raise CCowEmptyFileContentException(
            f"File content is empty: {type(file_content).__name__}"
        )
