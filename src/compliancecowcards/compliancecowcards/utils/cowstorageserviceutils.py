import requests
import pandas as pd
import logging
import hashlib
from compliancecowcards.utils import cowconstants, cowwsutils, cowdictutils

import os
import json
import io
import base64


COWStorageServiceProtocol = os.getenv("COW_STORAGE_SERVICE_PROTOCOL")
COWStorageServiceHostName = os.getenv("COW_STORAGE_SERVICE_HOST_NAME")
COWStorageServicePortNo = os.getenv("COW_STORAGE_SERVICE_PORT_NUMBER")
COWStorageServiceURL = "%s://%s:%s" % (COWStorageServiceProtocol,
                                       COWStorageServiceHostName, COWStorageServicePortNo)


def getfile(hashed_filename, header):
    urlPath = cowconstants.COWStorageServiceURL + \
        "/url-hash/download/"+hashed_filename
    response = requests.get(urlPath)
    if response.status_code == 200:
        return response.json()
    return {"error": 'File not found'}


def getfilehash(file_path, header):

    h = hashlib.new('ripemd160')
    h.update(bytes(file_path, 'utf-8'))
    req_body = {
        "url": file_path,
        "hash": h.hexdigest()
    }

    urlPath = cowconstants.COWStorageServiceURL+"/url-hash"
    return cowwsutils.post(urlPath, req_body, header)


def savefile(bucket_name, file_name, file_content, header):
    req_body = {
        "bucketName": bucket_name,
        "FileName": file_name,
        "FileContent": file_content
    }

    urlPath = cowconstants.COWStorageServiceURL+"/upload"
    # logging.info("POST_REQUEST", url=urlPath, reqData=req_body, header=header)
    response = requests.post(urlPath, json=req_body,
                             headers=cowwsutils.headerbuilder(header))

    if response.status_code == 200:
        return {"message": "Successfully uploaded"}
    return {"error": "Cannot upload the file"}


def save_and_get_file_hash(bucket_name, file_name, file_content, header) -> str and dict:
    file_resp = savefile(bucket_name, file_name, file_content, header)
    if cowdictutils.is_valid_key(file_resp, "error"):
        return "", file_resp["error"]
    file_path = bucket_name+"/"+file_name
    file_hash_resp = getfilehash(file_path, header)
    if cowdictutils.is_valid_key(file_hash_resp, "hash"):
        return file_hash_resp["hash"], None
    return "", {"error": "cannot create file hash"}


def deletefile(bucket_name, file_names, header):
    req_body = {
        "bucketName": bucket_name,
        "fileNamePrefixes": file_names
    }
    urlPath = cowconstants.COWStorageServiceURL+"/delete-files"
    # logging.info("POST_REQUEST", url=urlPath, reqData=req_body,
    #              header=cowwsutils.headerbuilder(header))
    response = requests.post(urlPath, json=req_body,
                             headers=cowwsutils.headerbuilder(header))
    if response.status_code == 204:
        return {"message": "Successfully deleted"}
    return {"error": "Cannot delete the file"}


def df_to_parquet_bytes(df=pd.DataFrame()):
    data = None
    if not df.empty:
        f = io.BytesIO()
        # replace empty dictionary, so the convertion won't fail
        df = pd.DataFrame(json.loads(df.to_json(orient='records').replace("{}","null")))
        df.to_parquet(f, index=False, engine='auto', compression='snappy')
        f.seek(0)
        content = f.read()
        data = base64.b64encode(content)
        data = str(data, 'utf-8')
    return data


def dict_to_json_bytes(data=None):

    data = json.dumps(data)
    # data = base64.b64encode(str.encode('utf-8'))
    return data
