package constants

const SystemObjects = `[
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
                "credtags": {
                    "type": [
                        "$TRIVY_REPO_TYPE"
                    ]
                },
                "sourcetype": "server",
                "loginurl": "$TRIVY_LOGIN_URL",
                "sshprivatekey": "$TRIVY_SSH_PRIVATE_KEY",
                "userID": "$TRIVY_USER_ID"
            }
        ],
        "Server": {
            "servername": "trivy-cli"
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
]`
