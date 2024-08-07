import requests
import logging
from compliancecowcards.utils import cowconstants, cowdictutils
import json
from django.http import JsonResponse


def post(urlPath, reqData, header):
    # logging.info("POST_REQUEST", url=urlPath, reqData=reqData, header=header)
    response = requests.post(urlPath, json=reqData,
                             headers=headerbuilder(header), verify=False)
    responseJSON = None
    if response.status_code != 204:
        responseJSON = response.json()

    return responseJSON


def put(urlPath, reqData, header):
    # logging.info("PUT_REQUEST", url=urlPath, reqData=reqData, header=header)
    response = requests.put(urlPath, json=reqData,
                            headers=headerbuilder(header))
    responseJSON = response.json()
    return responseJSON


def patch(urlPath, reqData, header):
    # logging.info("PATCH_REQUEST", url=urlPath, reqData=reqData, header=header)
    response = requests.patch(urlPath, json=reqData,
                              headers=headerbuilder(header))
    responseJSON = response.json()
    return responseJSON


def delete(urlPath, reqData, header):

    # logging.info("DELETE_REQUEST", url=urlPath, reqData=reqData, header=header)
    response = requests.delete(
        urlPath, json=reqData, headers=headerbuilder(header))
    responseJSON = None
    if response.status_code == 204:
        responseJSON = {"msg": "Successfully Deleted"}
    else:
        responseJSON = response.json()
    return responseJSON


def get(urlPath, params, header):
    # logging.info("GET_REQUEST", url=urlPath, header=header)
    response = requests.get(urlPath, params=params,
                            headers=headerbuilder(header))
    responseJSON = response.json()
    return responseJSON


def headerbuilder(header):
    if header:
        modifiedheader = dict()
        if cowdictutils.isValidKey(header, cowconstants.SecurityContext):
            securityCtx = header[cowconstants.SecurityContext]
            if not isinstance(securityCtx, str):
                securityCtx = json.dumps(securityCtx)

            # if not isinstance(header, str):
            #     if isinstance(header, dict):
            #         header = json.dumps(header)
            modifiedheader[cowconstants.SecurityContext] = securityCtx
            return modifiedheader
        elif cowdictutils.isValidKey(header, "Authorization"):
            return header
    return None


def getuserinfo(header):
    modifiedheader = dict()
    if header:
        if cowdictutils.isValidKey(header, cowconstants.SecurityContext):
            securityCtx = header[cowconstants.SecurityContext]
            if isinstance(securityCtx, str):
                securityCtx = json.loads(securityCtx)

            if cowdictutils.isValidKey(securityCtx, "user"):
                modifiedheader = securityCtx['user']
            elif cowdictutils.isValidKey(securityCtx, "ID") and cowdictutils.isValidKey(securityCtx, "DomainID"):
                modifiedheader = securityCtx

    return modifiedheader


def getJsonResponse(response):
    status = 200
    if 'status' in response:
        status = response['status']
        del response['status']
    return JsonResponse(response, safe=False, status=status)
