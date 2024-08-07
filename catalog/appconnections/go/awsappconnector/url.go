package awsappconnector

const (
	CLOUDTRAIL_URL               = "https://<<Region>>.console.aws.amazon.com/cloudtrail/home?region=<<Region>>#/trails/<<Resource>>"
	KMS_URL                      = "https://<<Region>>.console.aws.amazon.com/<<Service>>/home?region=<<Region>>#/kms/defaultKeys/<<Resource>>"
	VPC_URL                      = "https://<<Region>>.console.aws.amazon.com/vpcconsole/home?region=<<Region>>#VpcDetails:VpcId=<<Resource>>"
	CLOUD_WATCH_METRIC_ALARM_URL = "https://<<Region>>.console.aws.amazon.com/cloudwatch/home?region=<<Region>>#alarmsV2:alarm/<<Resource>>"
	CLOUD_WATCH_METRIC_FILER_URL = "https://<<Region>>.console.aws.amazon.com/cloudwatch/home?region=<<Region>>#logsV2:log-groups/log-group/<<ResourceParent>>/edit-metric-filter/<<Resource>>"
	IAM_USER_URL                 = "https://us-east-1.console.aws.amazon.com/iamv2/home?region=us-east-1#/users/details/<<Resource>>"
	IAM_ROLE_URL                 = "https://us-east-1.console.aws.amazon.com/iamv2/home?region=1#/roles/details/<<Resource>>"
	IAM_GROUP_URL                = "https://us-east-1.console.aws.amazon.com/iamv2/home?region=1#/groups/details/<<Resource>>"
	CLOUD_WATCH_LOG_GRP_URL      = "https://<<Region>>.console.aws.amazon.com/cloudwatch/home?region=<<Region>>#logsV2:log-groups/log-group/<<Resource>>"
	S3_BUCKET_URL                = "https://s3.console.aws.amazon.com/s3/buckets/<<Resource>>?region=<<Region>>&bucketType=general"
	BACKUP_VAULT_URL             = "https://<<Region>>.console.aws.amazon.com/backup/home?region=<<Region>>#/backupvaults/details/<<Resource>>"
	BACKUP_RECOVERY_PT_URL       = "https://<<Region>>.console.aws.amazon.com/backup/home?region=<<Region>>#/backupvaults/details/<<ResourceParent>>/<<Resource>>"
	IAM_POLICY_URL               = "https://<<Region>>.console.aws.amazon.com/iamv2/home?region=<<Region>>#/policies/details/<<Resource>>"
	CLOUD_WATCH_METRICS_LIST_URL = "https://<<Region>>.console.aws.amazon.com/cloudwatch/home?region=<<Region>>#metricsV2"
	CLOUDTRAIL_LIST_URL          = "https://<<Region>>.console.aws.amazon.com/cloudtrailv2/home?region=<<Region>>#/trails"
	IAM_USER_LIST_URL            = "https://<<Region>>.console.aws.amazon.com/iamv2/home?region=<<Region>>#/users"
	EC2_SECURITY_GROUP_URL       = "https://<<Region>>.console.aws.amazon.com/ec2/home?region=<<Region>>#SecurityGroup:groupId=<<Resource>>"
	RDS_DB_INSTANCE_URL          = "https://<<Region>>.console.aws.amazon.com/rds/home?region=<<Region>>#database:id=<<Resource>>"
)
