import os


COWStorageServiceProtocol = os.getenv("COW_STORAGE_SERVICE_PROTOCOL")
COWStorageServiceHostName = os.getenv("COW_STORAGE_SERVICE_HOST_NAME")
COWStorageServicePortNo = os.getenv("COW_STORAGE_SERVICE_PORT_NUMBER")
COWStorageServiceURL = "%s://%s:%s" % (COWStorageServiceProtocol,
                                       COWStorageServiceHostName, COWStorageServicePortNo)


COWDataServiceProtocol = os.getenv("COW_DATA_SERVICE_PROTOCOL")
COWDataServiceHostName = os.getenv("COW_DATA_SERVICE_HOST_NAME")
COWDataServicePortNo = os.getenv("COW_DATA_SERVICE_PORT_NUMBER")
COWDataServiceURL = "%s://%s:%s" % (COWDataServiceProtocol,
                                    COWDataServiceHostName, COWDataServicePortNo)


COWAttestServiceProtocol = os.getenv("COW_ATTEST_SERVICE_PROTOCOL")
COWAttestServiceHostName = os.getenv("COW_ATTEST_SERVICE_HOST_NAME")
COWAttestServicePortNo = os.getenv("COW_ATTEST_SERVICE_PORT_NUMBER")
COWAttestServiceURL = "%s://%s:%s" % (COWAttestServiceProtocol,
                                      COWAttestServiceHostName, COWAttestServicePortNo)

COWVersionControlServiceProtocol = os.getenv(
    "COW_VERSION_CONTROL_SERVICE_PROTOCOL")
COWVersionControlServiceHostName = os.getenv(
    "COW_VERSION_CONTROL_SERVICE_HOST_NAME")
COWVersionControlServicePortNo = os.getenv(
    "COW_VERSION_CONTROL_SERVICE_PORT_NUMBER")
COWVersionControlServiceURL = "%s://%s:%s" % (COWVersionControlServiceProtocol,
                                              COWVersionControlServiceHostName, COWVersionControlServicePortNo)

COWAuthServiceProtocol = os.getenv("COW_AUTH_SERVICE_PROTOCOL")
COWAuthServiceHostName = os.getenv("COW_AUTH_SERVICE_HOST_NAME")
COWAuthServicePortNo = os.getenv("COW_AUTH_SERVICE_PORT_NUMBER")
COWAuthServiceURL = "%s://%s:%s" % (COWAuthServiceProtocol,
                                    COWAuthServiceHostName, COWAuthServicePortNo)

COWSessionServiceProtocol = os.getenv("COW_SESSION_SERVICE_PROTOCOL")
COWSessionServiceHostName = os.getenv("COW_SESSION_SERVICE_HOST_NAME")
COWSessionServicePortNo = os.getenv("COW_SESSION_SERVICE_PORT_NUMBER")
COWSessionServiceURL = "%s://%s:%s" % (
    COWSessionServiceProtocol, COWSessionServiceHostName, COWSessionServicePortNo)

COWUserServiceProtocol = os.getenv("COW_USER_SERVICE_PROTOCOL")
COWUserServiceHostName = os.getenv("COW_USER_SERVICE_HOST_NAME")
COWUserServicePortNo = os.getenv("COW_USER_SERVICE_PORT_NUMBER")
COWUserServiceURL = "%s://%s:%s" % (COWUserServiceProtocol,
                                    COWUserServiceHostName, COWUserServicePortNo)

COWWorkflowServiceProtocol = os.getenv("COW_WORKFLOW_SERVICE_PROTOCOL")
COWWorkflowServiceHostName = os.getenv("COW_WORKFLOW_SERVICE_HOST_NAME")
COWWorkflowServicePortNo = os.getenv("COW_WORKFLOW_SERVICE_PORT_NUMBER")
COWWorkflowServiceURL = "%s://%s:%s" % (
    COWWorkflowServiceProtocol, COWWorkflowServiceHostName, COWWorkflowServicePortNo)

COWTransformServiceProtocol = os.getenv("COW_TRANSFORM_SERVICE_PROTOCOL")
COWTransformServiceHostName = os.getenv("COW_TRANSFORM_SERVICE_HOST_NAME")
COWTransformServicePortNo = os.getenv("COW_TRANSFORM_SERVICE_PORT_NUMBER")
COWTransformServiceURL = "%s://%s:%s" % (
    COWTransformServiceProtocol, COWTransformServiceHostName, COWTransformServicePortNo)

COWNotificationServiceProtocol = os.getenv("COW_NOTIFICATION_SERVICE_PROTOCOL")
COWNotificationServiceHostName = os.getenv(
    "COW_NOTIFICATION_SERVICE_HOST_NAME")
COWNotificationServicePortNo = os.getenv(
    "COW_NOTIFICATION_SERVICE_PORT_NUMBER")
COWNotificationServiceURL = "%s://%s:%s" % (
    COWNotificationServiceProtocol, COWNotificationServiceHostName, COWNotificationServicePortNo)


CNRecordOccuranceType = "occurance"
CNRecordHistoryType = "history"

StatusCompleted = "completed"
StatusStarted = "started"
StatusCancelled = "cancelled"

WebService = "webservice"
ReportService = "reportservice"

SecurityContext = "X-Cow-Security-Context"

ReadControls = "READ_CONTROLS"
ReadFrameworks = "READ_FRAMEWORKS"
ReadMasterControls = "READ_MASTER_CONTROLS"
ReadPlans = "READ_PLANS"
ReadReports = "READ_REPORTS"


NotAuthenticated = "not.authenticated"
CardTypeRequired = "card.type.required"
CardTypeNotAvailabe = "card.type.not.available"
NotAValidData = "not.valid.data"

VersionControlStatusSuccess = 1
VersionControlStatusFailure = 2

FileFormatTypeParquet = "parquet"
FileFormatTypeJSON = "json"
FileFormatTypeNDJSON = "ndjson"
FileFormatTypeCSV = "csv"


TransactionTypeJSON = {
    "evidence": 1,
    "exception": 2
}

FileStatusActive = "active"
FileStatusDeleted = "deleted"
FileStatusInActive = "inactive"


RecordLinkTypeSrc = "child"
RecordLinkTypePointer = "pointer"
RecordLinkTypeDuplicate = "duplicate"
RecordLinkTypeRelated = "related"

RecordLinkDirectionUniDirectional = "unidirection"
RecordLinkDirectionBiDirectional = "bidirection"

RecordDataTypeSource = "source"
RecordDataTypeChild = "child"

DateTimeFormat = "%Y/%m/%d %H:%M:%S"

DefaultSystemObjects = [
    {
        "App": {
            "appName": "minio",
            "appTags": {
                "app": [
                    "minio"
                ]
            },
            "appurl": "$MINIO_LOGIN_URL"
        },
        "Credentials": [
            {
                "credtags": {
                    "servicename": [
                        "minio"
                    ],
                    "servicetype": [
                        "storage"
                    ]
                },
                "loginurl": "$MINIO_LOGIN_URL",
                "othercredinfomap": {
                    "MINIO_ACCESS_KEY": "$MINIO_ROOT_USER",
                    "MINIO_SECRET_KEY": "$MINIO_ROOT_PASSWORD"
                }
            }
        ]
    },
    {
        "Credentials": [
            {
                "credtags": {
                    "type": [
                        "snyk_host"
                    ]
                },
                "loginurl": "$SNYK_LOGIN_URL",
                "othercredinfomap": {
                    "SnykToken": "$SNYK_TOKEN"
                },
                "sourcetype": "server",
                "sshprivatekey": "$SNYK_SSH_PRIVATE_KEY",
                "userID": "$SNYK_USER_ID"
            }
        ],
        "Server": {
            "serverName": "snyk",
            "servertags": {
                "app": [
                    "snyk cli"
                ]
            }
        }
    },
    {
        "App": {
            "appName": "cmdserver",
            "appTags": {
                "app": [
                    "cmdserver"
                ]
            },
            "appurl": "cmdserver:80"
        }
    },
    {
        "App": {
            "appName": "prereqcmd",
            "appTags": {
                "app": [
                    "prereqcmd"
                ]
            },
            "appurl": "cndorks:80"
        }
    },
    {
        "App": {
            "appName": "COW_API",
            "appTags": {
                "app": [
                    "cn_api_key_system"
                ]
            }
        },
        "Credentials": [
            {
                "othercredinfomap": {
                    "token": "$CCOW_AUTH_TOKEN"
                }
            }
        ]
    },
    {
        "Credentials": [
            {
                "sourcetype": "server",
                "loginurl": "$SEMGREP_LOGIN_URL",
                "sshprivatekey": "$SEMGREP_SSH_PRIVATE_KEY",
                "userID": "$SEMGREP_USER_ID"
            }
        ],
        "Server": {
            "servername": "semgrep-cli"
        }
    },
	{
		"Credentials": [
            {
				"othercredinfomap": {
					"OrgEmailID": "$QULAYS_SSL_LAB_ORG_EMAIL_ID"
				}
            }
        ],
		"App": {
            "appName": "ssltls",
            "appTags": {
                "app": [
                    "ssltls"
                ]
            }
        }
	}
]
