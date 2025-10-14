package awsappconnector

import (
	"applicationtypes/compliancecow"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	cowlibutils "cowlibrary/utils"

	awsV2 "github.com/aws/aws-sdk-go-v2/aws"
	configV2 "github.com/aws/aws-sdk-go-v2/config"
	credentialsV2 "github.com/aws/aws-sdk-go-v2/credentials"
	s3V2 "github.com/aws/aws-sdk-go-v2/service/s3"
	stsV2 "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/auditmanager"
	"github.com/aws/aws-sdk-go/service/backup"
	"github.com/aws/aws-sdk-go/service/cloudfront"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/directconnect"
	"github.com/aws/aws-sdk-go/service/docdb"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elasticache"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/keyspaces"
	"github.com/aws/aws-sdk-go/service/neptune"
	"github.com/aws/aws-sdk-go/service/networkfirewall"
	"github.com/aws/aws-sdk-go/service/qldb"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/route53"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/timestreaminfluxdb"
	"github.com/go-playground/validator/v10"
)

const (
	RESOURCE        = "<<Resource>>"
	REGION          = "<<Region>>"
	RESOURCE_PARENT = "<<ResourceParent>>"
)

// resource type is mapped with url
var resourceUrlMap = map[string]string{
	CLOUDTRAIL:                CLOUDTRAIL_URL,
	CLOUDTRAIL_LIST:           CLOUDTRAIL_LIST_URL,
	KMS:                       KMS_URL,
	CLOUD_WATCH_METRIC_ALARM:  CLOUD_WATCH_METRIC_ALARM_URL,
	CLOUD_WATCH_METRIC_FILTER: CLOUD_WATCH_METRIC_FILER_URL,
	IAM_USER:                  IAM_USER_URL,
	IAM_USER_LIST:             IAM_USER_LIST_URL,
	IAM_ROLE:                  IAM_ROLE_URL,
	IAM_GROUP:                 IAM_GROUP_URL,
	IAM_POLICY:                IAM_POLICY_URL,
	CLOUD_WATCH_LOG_GRP:       CLOUD_WATCH_LOG_GRP_URL,
	S3_BUCKET:                 S3_BUCKET_URL,
	BACKUP_VAULT:              BACKUP_VAULT_URL,
	BACKUP_RECOVERY_PT:        BACKUP_RECOVERY_PT_URL,
	CLOUD_WATCH_METRICS_LIST:  CLOUD_WATCH_METRICS_LIST_URL,
	EC2_SECURITY_GROUP:        EC2_SECURITY_GROUP_URL,
	IAM_PASSWORD_POLICY:       IAM_PASSWORD_POLICY_URL,
	EC2_INSTANCE:              EC_INSTANCE_URL,
	DYNAMO_DB_INSTANCE:        DYNAMO_DB_INSTANCE_URL,
	ELASTIC_CACHE:             ELASTIC_CACHE_URL,
	VPC:                       VPC_URL,
	NEPTUNE_INSTANCE:          NEPTUNE_URL,
	RDS_DB_INSTANCE:           RDS_DB_INSTANCE_URL,
	DOC_DB_INSTANCE:           DOCDB_URL,
	QLDB_LEDGER:               QLDB_URL,
	KEYSPACES:                 KEYSPACE_INSTANCE_URL,
	CLOUDFRONT_DISTRIBUTION:   CLOUD_FRONT_DISTRIBUTION_URL,
	DIRECTCONNECT_CONNECTION:  DIRECT_CONNECT_URL,
	ROUTE_53:                  ROUTE53_URL,
	NETWORK_FIREWALL:          NETWORK_FIREWALL_URL,
	TIMESTREAM_INSTANCE:       TIMESTREAM_URL,
}

type AWSRole struct {
	AccessKey string `json:"accessKey" yaml:"AccessKey"`
	SecretKey string `json:"secretKey" yaml:"SecretKey"`
	RoleARN   string `json:"roleARN" yaml:"RoleARN"`
}
type AWSIAM struct {
	AccessKey string `json:"accessKey" yaml:"AccessKey"`
	SecretKey string `json:"secretKey" yaml:"SecretKey"`
}

type UserDefinedCredentials struct {
	AWSRole AWSRole `json:"aWSRole" yaml:"AWSRole"`
	AWSIAM  AWSIAM  `json:"aWSIAM" yaml:"AWSIAM"`
}

type LinkedApplications struct {
	compliancecow.ComplianceCow `yaml:",inline"`
}

type AWSAppConnector struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"port"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
	Region                 []string                `json:"region" yaml:"Region"`
	LinkedApplications     *LinkedApplications     `json:"linkedApplications" yaml:"linkedApplications"`
}

type ErrorVO struct {
	Region string `json:"Region,omitempty"`
	Error  string `json:"Error"`
}

type Options struct {
	Region string
}

type FieldMetaVO struct {
	SrcConfig []map[string]interface{} `json:"srcConfig"`
}

func (thisObj *AWSAppConnector) Validate() (bool, error) {
	if !thisObj.IsEmptyAWSRole() {
		return thisObj.ValidateAWSRole()
	} else if !thisObj.IsEmptyAWSIAM() {
		return thisObj.ValidateAWSIAM()
	}
	return false, fmt.Errorf("Not a valid input")
}

func (thisObj *AWSAppConnector) IsEmptyAWSRole() bool {
	roleCreds := thisObj.UserDefinedCredentials.AWSRole
	return cowlibutils.IsEmpty(roleCreds.AccessKey) || cowlibutils.IsEmpty(roleCreds.SecretKey) || cowlibutils.IsEmpty(roleCreds.RoleARN)
}

func (thisObj *AWSAppConnector) CreateAWSSessionWithRole(options Options) (*session.Session, error) {
	roleCreds := thisObj.UserDefinedCredentials.AWSRole
	config := aws.Config{
		Region:      aws.String(options.Region),
		Credentials: credentials.NewStaticCredentials(roleCreds.AccessKey, roleCreds.SecretKey, ""),
	}
	sess, err := session.NewSession(&config)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return nil, errors.New(aerr.Message())
		}
		return nil, err
	}
	svc := sts.New(sess)
	sessionName := "compliancecowsession"
	assumeRoleOutput, err := svc.AssumeRole(&sts.AssumeRoleInput{
		RoleArn:         aws.String(roleCreds.RoleARN),
		RoleSessionName: aws.String(sessionName),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == "InvalidClientTokenId" {
				return nil, errors.New("Invalid AccessKey")
			} else if aerr.Code() == "SignatureDoesNotMatch" {
				return nil, errors.New("Invalid SecretKey")
			} else if aerr.Code() == "AccessDenied" {
				return nil, errors.New("Invalid RoleARN")
			} else {
				return nil, errors.New(aerr.Message())
			}
		}
		return nil, err
	}
	stsSess, err := session.NewSession(&aws.Config{
		Region:      aws.String(options.Region),
		Credentials: credentials.NewStaticCredentials(*assumeRoleOutput.Credentials.AccessKeyId, *assumeRoleOutput.Credentials.SecretAccessKey, *assumeRoleOutput.Credentials.SessionToken)})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == "InvalidClientID" {
				return nil, errors.New("Invalid AccessKey")
			} else if aerr.Code() == "SignatureDoesNotMatch" {
				return nil, errors.New("Invalid SecretKey")
			} else if aerr.Code() == "AccessDenied" {
				return nil, errors.New("Invalid RoleARN")
			} else {
				return nil, errors.New(aerr.Message())
			}
		}
		return nil, err
	}
	return stsSess, nil
}

func (thisObj *AWSAppConnector) ValidateAWSRole() (bool, error) {
	_, err := thisObj.CreateAWSSessionWithRole(Options{})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (awsrole *AWSRole) ValidateAttributes() string {
	var emptyAttributes []string
	errorResultStr := ""
	if awsrole.AccessKey == "" {
		emptyAttributes = append(emptyAttributes, "AccessKey")
	}
	if awsrole.SecretKey == "" {
		emptyAttributes = append(emptyAttributes, "SecretKey")
	}
	if awsrole.RoleARN == "" {
		emptyAttributes = append(emptyAttributes, "RoleARN")
	}
	if len(emptyAttributes) > 0 {
		errorResultStr = fmt.Sprintf("Invalid Credentials: %s", strings.Join(emptyAttributes, ", ")+" is empty")
	}
	return errorResultStr
}

func (awsiam *AWSIAM) ValidateAttributes() string {
	var emptyAttributes []string
	errorResultStr := ""
	if awsiam.AccessKey == "" {
		emptyAttributes = append(emptyAttributes, "AccessKey")
	}
	if awsiam.SecretKey == "" {
		emptyAttributes = append(emptyAttributes, "SecretKey")
	}
	if len(emptyAttributes) > 0 {
		errorResultStr = fmt.Sprintf("Invalid Credentials: %s", strings.Join(emptyAttributes, ", ")+" is empty")
	}
	return errorResultStr
}

func (thisObj *AWSAppConnector) IsEmptyAWSIAM() bool {
	iamCreds := thisObj.UserDefinedCredentials.AWSIAM
	return cowlibutils.IsEmpty(iamCreds.AccessKey) || cowlibutils.IsEmpty(iamCreds.SecretKey)
}

func (thisObj *AWSAppConnector) CreateAWSSessionWithAccessKeyV2(options Options) (*awsV2.Config, error) {
	iamCreds := thisObj.UserDefinedCredentials.AWSIAM

	cfg, err := configV2.LoadDefaultConfig(context.TODO(),
		configV2.WithRegion(options.Region),
		configV2.WithCredentialsProvider(credentialsV2.NewStaticCredentialsProvider(
			iamCreds.AccessKey, iamCreds.SecretKey, "",
		)),
	)

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return nil, errors.New(aerr.Message())
		}
		return nil, err
	}
	return &cfg, nil
}

func (thisObj *AWSAppConnector) CreateAWSSessionWithRoleV2(options Options) (*awsV2.Config, error) {
	roleCreds := thisObj.UserDefinedCredentials.AWSRole

	// Create initial config with static credentials
	cfg, err := configV2.LoadDefaultConfig(context.TODO(),
		configV2.WithRegion(options.Region),
		configV2.WithCredentialsProvider(
			credentialsV2.NewStaticCredentialsProvider(
				roleCreds.AccessKey,
				roleCreds.SecretKey,
				"", // session token (empty for initial credentials)
			),
		),
	)
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) {
			return nil, errors.New(ae.ErrorMessage())
		}
		return nil, err
	}

	// Create STS client
	stsClient := stsV2.NewFromConfig(cfg)
	sessionName := "compliancecowsession"

	// Assume role
	assumeRoleOutput, err := stsClient.AssumeRole(context.TODO(), &stsV2.AssumeRoleInput{
		RoleArn:         awsV2.String(roleCreds.RoleARN),
		RoleSessionName: awsV2.String(sessionName),
	})
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) {
			switch ae.ErrorCode() {
			case "InvalidClientTokenId":
				return nil, errors.New("Invalid AccessKey")
			case "SignatureDoesNotMatch":
				return nil, errors.New("Invalid SecretKey")
			case "AccessDenied":
				return nil, errors.New("Invalid RoleARN")
			default:
				return nil, errors.New(ae.ErrorMessage())
			}
		}
		return nil, err
	}

	// Create new config with assumed role credentials
	assumedRoleCfg, err := configV2.LoadDefaultConfig(context.TODO(),
		configV2.WithRegion(options.Region),
		configV2.WithCredentialsProvider(
			credentialsV2.NewStaticCredentialsProvider(
				*assumeRoleOutput.Credentials.AccessKeyId,
				*assumeRoleOutput.Credentials.SecretAccessKey,
				*assumeRoleOutput.Credentials.SessionToken,
			),
		),
	)
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) {
			switch ae.ErrorCode() {
			case "InvalidClientID", "InvalidClientTokenId":
				return nil, errors.New("Invalid AccessKey")
			case "SignatureDoesNotMatch":
				return nil, errors.New("Invalid SecretKey")
			case "AccessDenied":
				return nil, errors.New("Invalid RoleARN")
			default:
				return nil, errors.New(ae.ErrorMessage())
			}
		}
		return nil, err
	}

	return &assumedRoleCfg, nil
}

func (thisObj *AWSAppConnector) CreateAWSSessionWithAccessKey(options Options) (*session.Session, error) {
	iamCreds := thisObj.UserDefinedCredentials.AWSIAM
	config := aws.Config{
		Region:      aws.String(options.Region),
		Credentials: credentials.NewStaticCredentials(iamCreds.AccessKey, iamCreds.SecretKey, ""),
	}
	sess, err := session.NewSession(&config)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return nil, errors.New(aerr.Message())
		}
		return nil, err
	}
	return sess, nil
}

func (thisObj *AWSAppConnector) ValidateAWSIAM() (bool, error) {
	sess, err := thisObj.CreateAWSSessionWithAccessKey(Options{})
	if err != nil {
		return false, err
	}
	svc := iam.New(sess)
	_, err = svc.GetAccountAuthorizationDetails(&iam.GetAccountAuthorizationDetailsInput{})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == "InvalidClientTokenId" {
				return false, errors.New("Invalid AccessKey")
			} else if aerr.Code() == "SignatureDoesNotMatch" {
				return false, errors.New("Invalid SecretKey")
			} else {
				return false, errors.New(aerr.Message())
			}
		}
		return false, err
	}
	return true, nil
}

func (thisObj *AWSAppConnector) CreateAWSSession(options Options) (*session.Session, error) {
	var sess *session.Session
	var err error
	if !thisObj.IsEmptyAWSIAM() {
		sess, err = thisObj.CreateAWSSessionWithAccessKey(options)
		if err != nil {
			return nil, err
		}

	} else if !thisObj.IsEmptyAWSRole() {
		sess, err = thisObj.CreateAWSSessionWithRole(options)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("Not a valid application")
	}
	return sess, nil
}

func (thisObj *AWSAppConnector) CreateAWSSessionV2(options Options) (*awsV2.Config, error) {
	var cfg *awsV2.Config
	var err error
	if !thisObj.IsEmptyAWSIAM() {
		cfg, err = thisObj.CreateAWSSessionWithAccessKeyV2(options)
		if err != nil {
			return nil, err
		}
	} else if !thisObj.IsEmptyAWSRole() {
		cfg, err = thisObj.CreateAWSSessionWithRoleV2(options)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("Not a valid application")
	}
	return cfg, nil
}

// https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html
func (thisObj *AWSAppConnector) GetSecurityHubFindings(input *securityhub.GetFindingsInput) ([]*securityhub.AwsSecurityFinding, []ErrorVO) {
	var findings []*securityhub.AwsSecurityFinding
	var errorList []ErrorVO
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := securityhub.New(sess)
		err = svc.GetFindingsPages(input,
			func(page *securityhub.GetFindingsOutput, lastPage bool) bool {
				findings = append(findings, page.Findings...)
				return true
			})
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, aerr.Error())})
			} else {
				errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			}
			continue
		}
	}
	return findings, errorList
}

func (thisObj *AWSAppConnector) GetSecurityHubFindingsInput(inputs []string) []*securityhub.StringFilter {
	var strFilter []*securityhub.StringFilter
	for _, input := range inputs {
		filter := securityhub.StringFilter{
			Comparison: aws.String("EQUALS"),
			Value:      aws.String(input),
		}
		strFilter = append(strFilter, &filter)
	}
	return strFilter
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html
func (thisObj *AWSAppConnector) DownloadFileFromAWSS3Bucket(s3FileURI string) (string, *s3V2.GetObjectOutput, error) {
	s3URLObject, err := url.Parse(s3FileURI)
	if err != nil {
		return s3FileURI, nil, err
	}
	cfg, err := thisObj.CreateAWSSessionV2(Options{Region: thisObj.Region[0]})
	if err != nil {
		return s3FileURI, nil, err
	}

	s3Client := s3V2.NewFromConfig(*cfg)

	path := s3URLObject.Path
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}

	// Check if bucket exists and is accessible in this region
	bucketExists, bucketErr := thisObj.CheckBucketInRegion(context.TODO(), s3Client, s3URLObject.Host, thisObj.Region[0])
	if bucketErr != nil {
		return s3FileURI, nil, bucketErr
	}
	if !bucketExists {
		return s3FileURI, nil, fmt.Errorf("Bucket '%s' not found or not accessible in region '%s'", s3URLObject.Host, thisObj.Region[0])
	}

	// Check if key is a file
	if thisObj.IsFile(s3Client, s3URLObject.Host, path) {
		result, err := s3Client.GetObject(context.TODO(), &s3V2.GetObjectInput{
			Bucket: awsV2.String(s3URLObject.Host),
			Key:    awsV2.String(path),
		})
		if err != nil {
			return s3FileURI, nil, err
		}
		return s3FileURI, result, nil
	} else {
		lastestFileURI, err := thisObj.FindLatestFileRecursively(context.TODO(), s3Client, s3URLObject.Host, path)
		if err != nil {
			return lastestFileURI, nil, err
		}
		latestS3URLObject, err := url.Parse(lastestFileURI)
		if err != nil {
			return lastestFileURI, nil, err
		}

		path_ := latestS3URLObject.Path
		if strings.HasPrefix(path_, "/") {
			path_ = path_[1:]
		}

		result, err := s3Client.GetObject(context.TODO(), &s3V2.GetObjectInput{
			Bucket: awsV2.String(latestS3URLObject.Host),
			Key:    awsV2.String(path_),
		})
		if err != nil {
			return lastestFileURI, nil, err
		}
		return lastestFileURI, result, nil
	}
}

// CheckBucketInRegion checks if bucket exists and is accessible in the specified region
func (thisObj *AWSAppConnector) CheckBucketInRegion(ctx context.Context, s3Client *s3V2.Client, bucketName string, expectedRegion string) (bool, error) {
	// Method 1: Try HeadBucket first (most efficient)
	_, err := s3Client.HeadBucket(ctx, &s3V2.HeadBucketInput{
		Bucket: awsV2.String(bucketName),
	})

	if err == nil {
		// Bucket exists and is accessible in this region
		return true, nil
	}

	// Check specific error types
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "NotFound":
			return false, fmt.Errorf("Bucket '%s' does not exist", bucketName)
		case "Forbidden":
			return false, fmt.Errorf("Access denied to bucket '%s'", bucketName)
		case "MovedPermanently", "PermanentRedirect":
			// Bucket exists but in different region
			actualRegion, regionErr := thisObj.GetBucketRegionV2(ctx, s3Client, bucketName)
			if strings.Contains(fmt.Sprintf("%s", regionErr), "AccessDenied") {
				return false, fmt.Errorf("Access denied to bucket '%s'", bucketName)
			} else if regionErr != nil {
				return false, fmt.Errorf("Bucket exists in different region but failed to get region: %w", regionErr)
			}
			return false, fmt.Errorf("Bucket '%s' exists in region '%s', not '%s'", bucketName, actualRegion, expectedRegion)
		default:
			return false, fmt.Errorf("Failed to check bucket: %s", ae.ErrorMessage())
		}
	}

	return false, err
}

// GetBucketRegion retrieves the actual region of a bucket
func (thisObj *AWSAppConnector) GetBucketRegionV2(ctx context.Context, s3Client *s3V2.Client, bucketName string) (string, error) {

	location, err := s3Client.GetBucketLocation(ctx, &s3V2.GetBucketLocationInput{
		Bucket: awsV2.String(bucketName),
	})
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) {
			if ae.ErrorCode() == "NoSuchBucket" {
				return "", fmt.Errorf("bucket does not exist")
			}
		}
		return "", err
	}

	// GetBucketLocation returns empty string for us-east-1
	if location.LocationConstraint == "" {
		return "us-east-1", nil
	}

	return string(location.LocationConstraint), nil
}

func (thisObj *AWSAppConnector) FindLatestFileRecursively(ctx context.Context, s3Client *s3V2.Client, bucket, prefix string) (string, error) {
	// Normalize prefix
	prefix = strings.TrimPrefix(prefix, "/")
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	var latestTime time.Time
	var candidateKey string
	var candidateIsFolder bool

	// Step 1: Get subfolders and files
	folderInput := &s3V2.ListObjectsV2Input{
		Bucket:    awsV2.String(bucket),
		Prefix:    awsV2.String(prefix),
		Delimiter: awsV2.String("/"),
	}

	folderOutput, err := s3Client.ListObjectsV2(ctx, folderInput)
	if err != nil {
		return "", fmt.Errorf("error listing prefix contents: %v", err)
	}

	// Step 2: Find latest file
	for _, obj := range folderOutput.Contents {
		if *obj.Key == prefix {
			continue // skip self-folder object
		}
		if obj.LastModified.After(latestTime) {
			latestTime = *obj.LastModified
			candidateKey = *obj.Key
			candidateIsFolder = false
		}
	}

	// Step 3: Find latest subfolder
	for _, cp := range folderOutput.CommonPrefixes {
		subfolder := *cp.Prefix
		subfolderTime, err := thisObj.GetLastModifiedInFolder(ctx, s3Client, bucket, subfolder)
		if err != nil {
			return "", err
		}
		if subfolderTime.After(latestTime) {
			latestTime = subfolderTime
			candidateKey = subfolder
			candidateIsFolder = true
		}
	}

	// Step 4: Recurse or return
	if candidateIsFolder {
		return thisObj.FindLatestFileRecursively(ctx, s3Client, bucket, candidateKey)
	}

	if candidateKey != "" {
		return "s3://" + bucket + "/" + candidateKey, nil
	}

	return "", fmt.Errorf("no file found under prefix %s", prefix)
}

func (thisObj *AWSAppConnector) GetLastModifiedInFolder(ctx context.Context, s3Client *s3V2.Client, bucket, folder string) (time.Time, error) {
	var latest time.Time
	var token *string

	for {
		input := &s3V2.ListObjectsV2Input{
			Bucket:            awsV2.String(bucket),
			Prefix:            awsV2.String(folder),
			ContinuationToken: token,
		}
		output, err := s3Client.ListObjectsV2(ctx, input)
		if err != nil {
			return time.Time{}, fmt.Errorf("error listing folder contents: %v", err)
		}

		for _, obj := range output.Contents {
			if obj.LastModified.After(latest) {
				latest = *obj.LastModified
			}
		}

		if !*output.IsTruncated {
			break
		}
		token = output.NextContinuationToken
	}
	return latest, nil
}

func (thisObj *AWSAppConnector) IsFile(s3Client *s3V2.Client, bucket, key string) bool {
	_, err := s3Client.HeadObject(context.TODO(), &s3V2.HeadObjectInput{
		Bucket: awsV2.String(bucket),
		Key:    awsV2.String(key),
	})
	return err == nil
}

// https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountPasswordPolicy.html
func (thisObj *AWSAppConnector) GetAccountPasswordPolicy(input *iam.GetAccountPasswordPolicyInput) (*iam.PasswordPolicy, error) {
	var pwPolicy *iam.PasswordPolicy
	sess, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		return nil, err
	}
	svc := iam.New(sess)
	result, err := svc.GetAccountPasswordPolicy(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return nil, fmt.Errorf(aerr.Message())
		} else {
			return nil, err
		}
	} else {
		pwPolicy = result.PasswordPolicy
	}
	return pwPolicy, nil
}

// https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
func (thisObj *AWSAppConnector) GetCallerIdentity(input *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
	sess, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		return nil, err
	}
	svc := sts.New(sess)
	result, err := svc.GetCallerIdentity(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return nil, fmt.Errorf(aerr.Message())
		} else {
			return nil, err
		}
	}
	return result, nil
}

// https://docs.aws.amazon.com/IAM/latest/APIReference/API_GenerateCredentialReport.html
func (thisObj *AWSAppConnector) GenerateCredentialReport(input *iam.GenerateCredentialReportInput) (*iam.GenerateCredentialReportOutput, error) {
	var svc *iam.IAM
	for {
		session, err := thisObj.CreateAWSSession(Options{})
		if err != nil {
			return nil, err
		}
		svc = iam.New(session)
		result, err := svc.GenerateCredentialReport(input)
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				return nil, fmt.Errorf(aerr.Message())
			}
			return nil, err
		}
		if *result.State == "COMPLETE" {
			return result, nil
		}
	}
}

// https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetCredentialReport.html
func (thisObj *AWSAppConnector) GetCredentialReport(input *iam.GetCredentialReportInput) (*iam.GetCredentialReportOutput, error) {

	// generting the latest credential report
	_, err := thisObj.GenerateCredentialReport(&iam.GenerateCredentialReportInput{})
	if err != nil {
		return nil, err
	}
	session, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		return nil, err
	}
	svc := iam.New(session)
	result, err := svc.GetCredentialReport(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return nil, fmt.Errorf(aerr.Message())
		} else {
			return nil, err
		}
	}
	return result, nil

}

func (thisObj *AWSAppConnector) GetAWSAccountID() (string, error) {

	sess, err := thisObj.CreateAWSSession(Options{Region: ""})
	if err != nil {
		return "", fmt.Errorf("Error while creating session: %v", err)
	}
	svc := sts.New(sess)
	result, err := svc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("Error getting caller identity: %v", err)
	}

	return *result.Account, nil
}

func (thisObj *AWSAppConnector) GetRegionsList() ([]string, error) {

	var regions []string

	sess, err := thisObj.CreateAWSSession(Options{Region: ""})
	if err != nil {
		return regions, fmt.Errorf("Error while creating session: %v", err)
	}

	svc := ec2.New(sess)

	result, err := svc.DescribeRegions(&ec2.DescribeRegionsInput{})
	if err != nil {
		return regions, fmt.Errorf("Error describing regions: %v", err)
	}

	for _, region := range result.Regions {
		regions = append(regions, *region.RegionName)
	}

	return regions, nil
}

// func (thisObj *AWSAppConnector) GetSecurityGroups(include, exclude map[string][]string) ([]map[string]interface{}, []ErrorVO) {
func (thisObj *AWSAppConnector) GetSecurityGroups(includeSecurityGroup, excludeSecurityGroup []string, accountID string) ([]map[string]interface{}, []ErrorVO) {

	//sample include criteria ---> account/2345678987654/region/us-east-1/securitygroup/*
	var securityGroupsData []map[string]interface{}
	var errorList []ErrorVO

	input := &ec2.DescribeSecurityGroupsInput{}
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := ec2.New(sess)
		var specifiedSecurityGroup bool
		if len(includeSecurityGroup) > 0 {
			specifiedSecurityGroup = true
		}

		err = svc.DescribeSecurityGroupsPages(input,
			func(page *ec2.DescribeSecurityGroupsOutput, lastPage bool) bool {

				if specifiedSecurityGroup {
					sgList := make([]string, 0)
					for _, sg := range page.SecurityGroups {
						sgList = append(sgList, fmt.Sprintf("%v", *sg.GroupName))
					}
					for _, includeSecurityGroup_ := range includeSecurityGroup {
						if !slices.Contains(sgList, includeSecurityGroup_) {
							errorList = append(errorList,
								ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in SecurityGroup.", includeSecurityGroup_)})
						}
					}
				}

				for _, sg := range page.SecurityGroups {

					if specifiedSecurityGroup {
						if !slices.Contains(includeSecurityGroup, fmt.Sprintf("%v", *sg.GroupName)) {
							continue
						}
					}

					if slices.Contains(excludeSecurityGroup, fmt.Sprintf("%v", *sg.GroupName)) {
						continue
					}

					temp := make(map[string]interface{})

					// Serialize the SecurityGroup struct to JSON
					serialized, err := json.Marshal(sg)
					if err != nil {
						errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ; Error marshaling SecurityGroup: %v", region, err.Error())})
						return true

					}

					// Deserialize the JSON to a map
					err = json.Unmarshal(serialized, &temp)
					if err != nil {
						errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ; Error Unmarshaling SecurityGroup: %v", region, err.Error())})
						return true
					}
					temp["ResourceID"] = sg.GroupId
					securityGroupsData = append(securityGroupsData, temp)
				}

				return true
			})

		//
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, aerr.Error())})
				continue
			}
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
	}

	return securityGroupsData, errorList
}

// func (thisObj *AWSAppConnector) GetIamPolicies(include, exclude map[string][]string) ([]map[string]interface{}, []ErrorVO) {
func (thisObj *AWSAppConnector) GetIamPolicies(includeIamPolicy, excludeIamPolicy []string, accountID string) ([]map[string]interface{}, []ErrorVO) {
	var policiesList []*iam.Policy
	iamPoliciesData := make([]map[string]interface{}, 0)
	var errorList []ErrorVO

	input := &iam.ListPoliciesInput{}

	sess, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		errorList = append(errorList, ErrorVO{Error: err.Error()})
		return iamPoliciesData, errorList
	}
	svc := iam.New(sess)

	var specifiedPolicy bool
	if len(includeIamPolicy) > 0 {
		specifiedPolicy = true
	}
	err = svc.ListPoliciesPages(input,
		func(page *iam.ListPoliciesOutput, lastPage bool) bool {
			policiesList = append(policiesList, page.Policies...)
			return true
		})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			errorList = append(errorList, ErrorVO{Error: aerr.Message()})
			return iamPoliciesData, errorList
		}
		errorList = append(errorList, ErrorVO{Error: err.Error()})
		return iamPoliciesData, errorList
	}

	if specifiedPolicy {
		policiesListWithNames := make([]string, 0)
		for _, policy := range policiesList {
			policiesListWithNames = append(policiesListWithNames, fmt.Sprintf("%v", *policy.PolicyName))
		}
		for _, includeIamPolicy_ := range includeIamPolicy {
			if !slices.Contains(policiesListWithNames, includeIamPolicy_) {
				errorList = append(errorList,
					ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in IAM Policy.", includeIamPolicy_)})
			}
		}
	}

	for _, policy := range policiesList {

		if specifiedPolicy {
			if !slices.Contains(includeIamPolicy, fmt.Sprintf("%v", *policy.PolicyName)) {
				continue
			}
		}

		if slices.Contains(excludeIamPolicy, fmt.Sprintf("%v", *policy.PolicyName)) {
			continue
		}

		params := &iam.GetPolicyInput{
			PolicyArn: aws.String(*policy.Arn),
		}

		resp, err := svc.GetPolicy(params)
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: err.Error()})
			continue
		}

		if resp.Policy != nil && resp.Policy.DefaultVersionId != nil {
			versionID := aws.StringValue(resp.Policy.DefaultVersionId)

			versionParams := &iam.GetPolicyVersionInput{
				PolicyArn: aws.String(*policy.Arn),
				VersionId: aws.String(versionID),
			}

			versionResp, err := svc.GetPolicyVersion(versionParams)
			if err != nil {
				errorList = append(errorList, ErrorVO{Error: err.Error()})
				continue
			}

			if versionResp.PolicyVersion != nil && versionResp.PolicyVersion.Document != nil {
				policyDocument := aws.StringValue(versionResp.PolicyVersion.Document)
				decodedPolicyDocument, err := url.QueryUnescape(policyDocument)
				if err != nil {
					errorList = append(errorList, ErrorVO{Error: err.Error()})
					continue
				}

				var iamPoliciesDataTemp map[string]interface{}
				err = json.Unmarshal([]byte(decodedPolicyDocument), &iamPoliciesDataTemp)
				if err != nil {
					errorList = append(errorList, ErrorVO{Error: err.Error()})
					continue
				}
				iamPoliciesDataTemp["policy"] = resp.Policy
				iamPoliciesDataTemp["ResourceID"] = resp.Policy.PolicyId
				iamPoliciesDataTemp["ResourceName"] = resp.Policy.PolicyName
				iamPoliciesDataTemp["AccountID"] = accountID
				iamPoliciesData = append(iamPoliciesData, iamPoliciesDataTemp)

			}
		}
	}

	return iamPoliciesData, errorList
}
func (thisObj *AWSAppConnector) GetIamUsers(includeIamUsers, excludeIamUsers []string, accountID string) ([]*IamUser, []ErrorVO) {
	var usersList []*iam.User
	userListOutputData := make([]*IamUser, 0)
	var errorList []ErrorVO

	input := &iam.ListUsersInput{}

	sess, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		errorList = append(errorList, ErrorVO{Error: err.Error()})
		return userListOutputData, errorList
	}
	svc := iam.New(sess)

	var specifiedUser bool
	if len(includeIamUsers) > 0 {
		specifiedUser = true
	}
	err = svc.ListUsersPages(input,
		func(page *iam.ListUsersOutput, lastPage bool) bool {
			usersList = append(usersList, page.Users...)
			return true
		})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			errorList = append(errorList, ErrorVO{Error: aerr.Message()})
			return userListOutputData, errorList
		}
		errorList = append(errorList, ErrorVO{Error: err.Error()})
		return userListOutputData, errorList
	}

	for _, user := range usersList {

		if specifiedUser {
			if !slices.Contains(includeIamUsers, fmt.Sprintf("%v", *user.UserName)) {
				continue
			}
			includeIamUsers = thisObj.removeFromStringSlice(includeIamUsers, fmt.Sprintf("%v", *user.UserName))
		}

		if slices.Contains(excludeIamUsers, fmt.Sprintf("%v", *user.UserName)) {
			continue
		}

		temp := &IamUser{
			User:       user,
			ResourceID: *user.UserId,
		}
		userListOutputData = append(userListOutputData, temp)
	}
	if len(includeIamUsers) > 0 {
		for _, includeResource := range includeIamUsers {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in IAM users.", includeResource)})

		}
	}
	return userListOutputData, errorList
}
func (thisObj *AWSAppConnector) GetIamRoles(includeIamRoles, excludeIamRoles []string, accountID string) ([]*IamRole, []ErrorVO) {
	var rolesList []*iam.Role
	rolesListOutputData := make([]*IamRole, 0)
	var errorList []ErrorVO

	input := &iam.ListRolesInput{}

	sess, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		errorList = append(errorList, ErrorVO{Error: err.Error()})
		return rolesListOutputData, errorList
	}
	svc := iam.New(sess)

	var specifiedRole bool
	if len(includeIamRoles) > 0 {
		specifiedRole = true
	}
	err = svc.ListRolesPages(input,
		func(page *iam.ListRolesOutput, lastPage bool) bool {
			rolesList = append(rolesList, page.Roles...)
			return true
		})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			errorList = append(errorList, ErrorVO{Error: aerr.Message()})
			return rolesListOutputData, errorList
		}
		errorList = append(errorList, ErrorVO{Error: err.Error()})
		return rolesListOutputData, errorList
	}

	for _, role := range rolesList {

		if specifiedRole {
			if !slices.Contains(includeIamRoles, fmt.Sprintf("%v", *role.RoleName)) {
				continue
			}
			includeIamRoles = thisObj.removeFromStringSlice(includeIamRoles, fmt.Sprintf("%v", *role.RoleName))
		}

		if slices.Contains(excludeIamRoles, fmt.Sprintf("%v", *role.RoleName)) {
			continue
		}

		temp := &IamRole{
			Role:       role,
			ResourceID: *role.RoleId,
		}
		rolesListOutputData = append(rolesListOutputData, temp)
	}
	if len(includeIamRoles) > 0 {
		for _, includeResource := range includeIamRoles {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in IAM roles.", includeResource)})

		}
	}
	return rolesListOutputData, errorList
}

// func (thisObj *AWSAppConnector) GetS3ResourceData(include, exclude map[string][]string) ([]BucketDetails, []ErrorVO) {
func (thisObj *AWSAppConnector) GetS3ResourceData(includeBucketNames, excludeBucketNames []string, accountID string) ([]BucketDetails, []ErrorVO) {
	outputRecords := []BucketDetails{}
	var errorList []ErrorVO

	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := s3.New(sess)

		result, err := svc.ListBuckets(nil)
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		var specifiedBuckets bool
		if len(includeBucketNames) > 0 {
			specifiedBuckets = true
		}

		bucketeListWithNames := make([]string, 0)
		if specifiedBuckets {
			for _, buckets := range result.Buckets {
				bucketeListWithNames = append(bucketeListWithNames, fmt.Sprintf("%v", *buckets.Name))
			}
			for _, includeBucketNames_ := range includeBucketNames {
				if !slices.Contains(bucketeListWithNames, includeBucketNames_) {
					errorList = append(errorList,
						ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in S3 bucket.", includeBucketNames_)})
				}
			}
		}

		for _, b := range result.Buckets {

			bucketName := *b.Name
			bucketARN := fmt.Sprintf("arn:aws:s3:::%s", bucketName)
			if specifiedBuckets {
				if !slices.Contains(includeBucketNames, bucketName) {
					continue
				}
			}

			if slices.Contains(excludeBucketNames, bucketName) {
				continue
			}

			locationResult, err := svc.GetBucketLocation(&s3.GetBucketLocationInput{
				Bucket: &bucketName,
			})
			if err != nil {
				errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
				continue
			}
			bucketRegion := ""
			if locationResult != nil {
				if locationResult.LocationConstraint != nil {
					bucketRegion = *locationResult.LocationConstraint
				}
			}

			if (locationResult.LocationConstraint == nil && region == "us-east-1") || (bucketRegion == region) {

				loggingParams := &s3.GetBucketLoggingInput{
					Bucket: aws.String(bucketName),
				}
				var logConfig *s3.GetBucketLoggingOutput

				logConfig, err = svc.GetBucketLogging(loggingParams)
				if err != nil {
					errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
					continue
				}

				isLogEnabled := false
				targetBucket := ""
				if logConfig.LoggingEnabled != nil && *logConfig.LoggingEnabled.TargetBucket != "" {
					isLogEnabled = true
					targetBucket = *logConfig.LoggingEnabled.TargetBucket
				}

				outputRecord := BucketDetails{
					ResourceName: bucketName,
					CreationDate: b.CreationDate,
					Region:       region,
					ResourceID:   bucketName,
					LogEnabled:   isLogEnabled,
					TargetBucket: targetBucket,
					AccountID:    accountID,
					ResourceARN:  bucketARN,
				}

				outputRecords = append(outputRecords, outputRecord)
			}

		}

	}
	return outputRecords, errorList
}

func (thisObj *AWSAppConnector) GetEC2ResourceData(includeInstaces, excludeInstances []string, accountID string) ([]*EC2, []ErrorVO) {
	instanceListData := make([]*EC2, 0)
	var errorList []ErrorVO
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := ec2.New(sess)
		ec2result, err := svc.DescribeInstances(nil)
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		var specifiedInstances bool
		if len(includeInstaces) > 0 {
			specifiedInstances = true
		}
		for _, reservation := range ec2result.Reservations {
			var instanceList = reservation.Instances
			for _, instance := range instanceList {
				ResourceName := aws.String("")
				for _, v := range instance.Tags {
					name := aws.String("Name")
					if *(v.Key) == *name {
						ResourceName = v.Value
					}
				}
				if specifiedInstances {
					if !slices.Contains(includeInstaces, *ResourceName) {
						continue
					}
					includeInstaces = thisObj.removeFromStringSlice(includeInstaces, fmt.Sprintf("%v", *ResourceName))
				}
				if slices.Contains(excludeInstances, *ResourceName) {
					continue
				}
				temp := &EC2{
					Instance:    instance,
					ResourceID:  *instance.InstanceId,
					InstanceARN: fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, accountID, *instance.InstanceId),
				}
				instanceListData = append(instanceListData, temp)
			}
		}

	}
	if len(includeInstaces) > 0 {
		for _, includeResource := range includeInstaces {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in EC2 instances.", includeResource)})

		}
	}
	return instanceListData, errorList

}
func (thisObj *AWSAppConnector) GetDynamoDBResourceData(includeDB, excludeDB []string, accountID string) ([]*DynamoDB, []ErrorVO) {
	dynamoDBtableList := make([]*DynamoDB, 0)
	var errorList []ErrorVO
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := dynamodb.New(sess)
		dynamoDBresult, err := svc.ListTables(nil)
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		var specifiedTables bool
		if len(includeDB) > 0 {
			specifiedTables = true
		}

		for _, table := range dynamoDBresult.TableNames {
			if specifiedTables {
				if !slices.Contains(includeDB, *table) {
					continue
				}
				includeDB = thisObj.removeFromStringSlice(includeDB, fmt.Sprintf("%v", *table))

			}
			if slices.Contains(excludeDB, *table) {
				continue
			}
			DescribeTableInput := &dynamodb.DescribeTableInput{TableName: table}
			tableData, err := svc.DescribeTable(DescribeTableInput)
			if err != nil {
				errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
				continue
			}
			temp := &DynamoDB{
				TableDescription: tableData.Table,
				ResourceID:       *tableData.Table.TableId,
			}
			dynamoDBtableList = append(dynamoDBtableList, temp)
		}

	}
	if len(includeDB) > 0 {
		for _, includeResource := range includeDB {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in dynamodb.", includeResource)})

		}
	}
	return dynamoDBtableList, errorList

}
func (thisObj *AWSAppConnector) GetElasticCacheResourceData(includeDB, excludeDB []string, accountID string) ([]*ElasticCache, []ErrorVO) {
	cacheClusterList := make([]*ElasticCache, 0)
	var errorList []ErrorVO
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := elasticache.New(sess)
		elasticCacheResult, err := svc.DescribeCacheClusters(nil)
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		var specifiedTables bool
		if len(includeDB) > 0 {
			specifiedTables = true
		}

		for _, cacheCluster := range elasticCacheResult.CacheClusters {
			if specifiedTables {
				if !slices.Contains(includeDB, *cacheCluster.ReplicationGroupId) {
					continue
				}
				includeDB = thisObj.removeFromStringSlice(includeDB, fmt.Sprintf("%v", *cacheCluster.ReplicationGroupId))
			}
			if slices.Contains(excludeDB, *cacheCluster.ReplicationGroupId) {
				continue
			}
			temp := &ElasticCache{
				CacheCluster: cacheCluster,
				ResourceID:   *cacheCluster.CacheClusterId,
			}
			cacheClusterList = append(cacheClusterList, temp)
		}

	}
	if len(includeDB) > 0 {
		for _, includeResource := range includeDB {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in elasticcache.", includeResource)})

		}
	}
	return cacheClusterList, errorList

}
func (thisObj *AWSAppConnector) GetTimeStreamResourceData(includeDB, excludeDB []string, accountID string) ([]*TimeStream, []ErrorVO) {
	timeStreamDBInstanceList := make([]*TimeStream, 0)
	var errorList []ErrorVO
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := timestreaminfluxdb.New(sess)

		timeStreamResult, err := svc.ListDbInstances(nil)
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		var specifiedDB bool
		if len(includeDB) > 0 {
			specifiedDB = true
		}

		for _, timeStreamDB := range timeStreamResult.Items {
			if specifiedDB {
				if !slices.Contains(includeDB, *timeStreamDB.Name) {
					continue
				}
				includeDB = thisObj.removeFromStringSlice(includeDB, fmt.Sprintf("%v", *timeStreamDB.Name))
			}
			if slices.Contains(excludeDB, *timeStreamDB.Name) {
				continue
			}

			temp := &TimeStream{
				DbInstanceSummary: timeStreamDB,
				ResourceID:        *timeStreamDB.Id,
			}

			timeStreamDBInstanceList = append(timeStreamDBInstanceList, temp)
		}

	}
	if len(includeDB) > 0 {
		for _, includeResource := range includeDB {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in timestreamDB.", includeResource)})

		}
	}
	return timeStreamDBInstanceList, errorList
}
func (thisObj *AWSAppConnector) GetNeptuneResourceData(includeDB, excludeDB []string, accountID string) ([]*Neptune, []ErrorVO) {
	neptuneDBInstanceList := make([]*Neptune, 0)
	var errorList []ErrorVO
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := neptune.New(sess)
		neptuneResult, err := svc.DescribeDBInstances(nil)
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		var specifiedDB bool
		if len(includeDB) > 0 {
			specifiedDB = true
		}

		for _, neptuneDB := range neptuneResult.DBInstances {
			var resourceName string
			if neptuneDB.DBInstanceIdentifier != nil {
				resourceName = *neptuneDB.DBInstanceIdentifier
			} else {
				resourceName = *neptuneDB.DBName
			}
			if specifiedDB {
				if !slices.Contains(includeDB, resourceName) {
					continue
				}
				includeDB = thisObj.removeFromStringSlice(includeDB, fmt.Sprintf("%v", resourceName))

			}
			if neptuneDB.DBInstanceIdentifier != nil && slices.Contains(excludeDB, resourceName) {
				continue
			}
			temp := &Neptune{
				DBInstance: neptuneDB,
				ResourceID: resourceName,
			}
			neptuneDBInstanceList = append(neptuneDBInstanceList, temp)
		}

	}
	if len(includeDB) > 0 {
		for _, includeResource := range includeDB {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in neptune.", includeResource)})

		}
	}
	return neptuneDBInstanceList, errorList
}
func (thisObj *AWSAppConnector) GetRDSResourceData(includeDB, excludeDB []string, accountID string) ([]*RDS, []ErrorVO) {
	RDSDBInstanceList := make([]*RDS, 0)
	var errorList []ErrorVO
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := rds.New(sess)
		RDSResult, err := svc.DescribeDBInstances(nil)
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		var specifiedDB bool
		if len(includeDB) > 0 {
			specifiedDB = true
		}

		for _, rdsDB := range RDSResult.DBInstances {
			var dbname *string
			if rdsDB.DBInstanceIdentifier != nil {
				dbname = rdsDB.DBInstanceIdentifier
			} else {
				dbname = rdsDB.DBName
			}
			if specifiedDB {
				if !slices.Contains(includeDB, *dbname) {
					continue
				}
				includeDB = thisObj.removeFromStringSlice(includeDB, fmt.Sprintf("%v", *dbname))
			}
			if slices.Contains(excludeDB, *dbname) {
				continue
			}
			temp := &RDS{
				DBInstance: rdsDB,
				ResourceID: *dbname,
			}
			RDSDBInstanceList = append(RDSDBInstanceList, temp)
		}

	}
	if len(includeDB) > 0 {
		for _, includeResource := range includeDB {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in RDS.", includeResource)})
		}
	}
	return RDSDBInstanceList, errorList
}
func (thisObj *AWSAppConnector) GetDocumentDBResourceData(includeDB, excludeDB []string, accountID string) ([]*DocDB, []ErrorVO) {
	DocDBInstanceList := make([]*DocDB, 0)
	var errorList []ErrorVO
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := docdb.New(sess)
		docDBResult, err := svc.DescribeDBInstances(nil)
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		var specifiedDB bool
		if len(includeDB) > 0 {
			specifiedDB = true
		}

		for _, docDB := range docDBResult.DBInstances {
			if specifiedDB {
				if !slices.Contains(includeDB, *docDB.DBInstanceIdentifier) {
					continue
				}
				includeDB = thisObj.removeFromStringSlice(includeDB, fmt.Sprintf("%v", *docDB.DBInstanceIdentifier))
			}
			if slices.Contains(excludeDB, *docDB.DBInstanceIdentifier) {
				continue
			}
			temp := &DocDB{
				DBInstance: docDB,
				ResourceID: *docDB.DBInstanceIdentifier,
			}
			DocDBInstanceList = append(DocDBInstanceList, temp)
		}

	}
	if len(includeDB) > 0 {
		for _, includeResource := range includeDB {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in docDB.", includeResource)})
		}
	}
	return DocDBInstanceList, errorList
}
func (thisObj *AWSAppConnector) GetQLDBResourceData(includeDB, excludeDB []string, accountID string) ([]*QLDB, []ErrorVO) {
	QLDBInstanceList := make([]*qldb.LedgerSummary, 0)
	outputList := make([]*QLDB, 0)
	var errorList []ErrorVO
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := qldb.New(sess)
		err = svc.ListLedgersPages(nil, func(page *qldb.ListLedgersOutput, lastPage bool) bool {
			QLDBInstanceList = append(QLDBInstanceList, page.Ledgers...)
			return true
		})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		var specifiedDB bool
		if len(includeDB) > 0 {
			specifiedDB = true
		}

		for _, qlDB := range QLDBInstanceList {
			if specifiedDB {
				if !slices.Contains(includeDB, *qlDB.Name) {
					continue
				}
				includeDB = thisObj.removeFromStringSlice(includeDB, fmt.Sprintf("%v", *qlDB.Name))

			}
			if slices.Contains(excludeDB, *qlDB.Name) {
				continue
			}
			temp := &QLDB{
				LedgerSummary: qlDB,
				ResourceID:    *qlDB.Name,
			}
			outputList = append(outputList, temp)
		}

	}
	if len(includeDB) > 0 {
		for _, includeResource := range includeDB {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in QLDB.", includeResource)})
		}
	}
	return outputList, errorList
}
func (thisObj *AWSAppConnector) GetKeySpacesBResourceData(includeDB, excludeDB []string, accountID string) ([]*Keyspaces, []ErrorVO) {
	outputList := make([]*Keyspaces, 0)
	var errorList []ErrorVO
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := keyspaces.New(sess)
		keyspacesData, err := svc.ListKeyspaces(nil)
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		var specifiedDB bool
		if len(includeDB) > 0 {
			specifiedDB = true
		}
		defaultKeySpaces := []string{"system", "system_schema", "system_schema_mcs", "system_multiregion_info"} // aws default keyspaces

		for _, keySpace := range keyspacesData.Keyspaces {
			if specifiedDB {
				if !slices.Contains(includeDB, *keySpace.KeyspaceName) {
					continue
				}
				includeDB = thisObj.removeFromStringSlice(includeDB, fmt.Sprintf("%v", *keySpace.KeyspaceName))

			}

			if slices.Contains(excludeDB, *keySpace.KeyspaceName) || slices.Contains(defaultKeySpaces, *keySpace.KeyspaceName) {
				continue
			}
			_, err := svc.GetKeyspace(&keyspaces.GetKeyspaceInput{
				KeyspaceName: keySpace.KeyspaceName,
			})
			if err != nil {
				errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
				continue
			}
			temp := &Keyspaces{
				KeyspaceSummary: keySpace,
				ResourceID:      *keySpace.KeyspaceName,
			}
			outputList = append(outputList, temp)
		}
	}
	if len(includeDB) > 0 {
		for _, includeResource := range includeDB {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in Keyspaces.", includeResource)})
		}
	}
	return outputList, errorList
}
func (thisObj *AWSAppConnector) GetVPCBResourceData(includeDB, excludeDB []string, accountID string) ([]*EC2VPC, []ErrorVO) {

	outputVPCList := make([]*EC2VPC, 0)
	var errorList []ErrorVO
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := ec2.New(sess)
		VPCList, err := thisObj.GetEc2Vpcs(svc, &ec2.DescribeVpcsInput{})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		var specifiedDB bool
		if len(includeDB) > 0 {
			specifiedDB = true
		}

		for _, VPC := range VPCList {
			ResourceName := aws.String("")
			name := aws.String("Name")
			for _, v := range VPC.Tags {

				if v.Key != nil && *(v.Key) == *name {
					if v.Value != nil {
						ResourceName = v.Value
						break
					}
				}
			}
			if specifiedDB {
				if !slices.Contains(includeDB, *ResourceName) {
					continue
				}
				includeDB = thisObj.removeFromStringSlice(includeDB, fmt.Sprintf("%v", *ResourceName))
			}
			if slices.Contains(excludeDB, *ResourceName) {
				continue
			}
			temp := &EC2VPC{
				Vpc:        VPC,
				ResourceID: *VPC.VpcId,
			}
			outputVPCList = append(outputVPCList, temp)
		}
	}
	if len(includeDB) > 0 {
		for _, includeResource := range includeDB {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in VPC.", includeResource)})
		}
	}
	return outputVPCList, errorList
}
func (thisObj *AWSAppConnector) GetCloudFrontResourceData(includeDistribution, excludeDistribution []string, accountID string) ([]*CloudFront, []ErrorVO) {
	DistributionList := make([]*CloudFront, 0)
	var cfDistributions *cloudfront.ListDistributionsOutput
	var errorList []ErrorVO
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := cloudfront.New(sess)
		cfDistributions, err = svc.ListDistributions(nil)
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		var specifiedDB bool
		if len(includeDistribution) > 0 {
			specifiedDB = true
		}

		for _, distribution := range cfDistributions.DistributionList.Items {
			if specifiedDB {
				if !slices.Contains(includeDistribution, *distribution.Comment) {
					continue
				}
				includeDistribution = thisObj.removeFromStringSlice(includeDistribution, fmt.Sprintf("%v", *distribution.Comment))
			}
			if slices.Contains(excludeDistribution, *distribution.Comment) {
				continue
			}
			temp := &CloudFront{
				DistributionSummary: distribution,
				ResourceID:          *distribution.Id,
			}
			DistributionList = append(DistributionList, temp)
		}
	}
	if len(includeDistribution) > 0 {
		for _, includeResource := range includeDistribution {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in cloudfront.", includeResource)})
		}
	}
	return DistributionList, errorList
}
func (thisObj *AWSAppConnector) GetDirectConnectResourceData(includeDistribution, excludeDistribution []string, accountID string) ([]*DirectConnect, []ErrorVO) {
	connectionList := make([]*DirectConnect, 0)
	var dcConnections *directconnect.Connections
	var errorList []ErrorVO
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := directconnect.New(sess)
		dcConnections, err = svc.DescribeConnections(nil)
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		var specifiedDB bool
		if len(includeDistribution) > 0 {
			specifiedDB = true
		}

		for _, connectionData := range dcConnections.Connections {
			if specifiedDB {
				if !slices.Contains(includeDistribution, *connectionData.ConnectionName) {
					continue
				}
				includeDistribution = thisObj.removeFromStringSlice(includeDistribution, fmt.Sprintf("%v", *connectionData.ConnectionName))
			}
			if slices.Contains(excludeDistribution, *connectionData.ConnectionName) {
				continue
			}
			temp := &DirectConnect{
				Connection: connectionData,
				ResourceID: *connectionData.ConnectionId,
			}
			connectionList = append(connectionList, temp)
		}
	}
	if len(includeDistribution) > 0 {
		for _, includeResource := range includeDistribution {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in direct connect.", includeResource)})
		}
	}
	return connectionList, errorList
}
func (thisObj *AWSAppConnector) GetRoute53ResourceData(includeHostZones, excludeHostZones []string, accountID string) ([]*Route53, []ErrorVO) {
	resultList := make([]*Route53, 0)
	var route53HostList *route53.ListHostedZonesOutput
	var errorList []ErrorVO
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := route53.New(sess)
		route53HostList, err = svc.ListHostedZones(nil)
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		var specifiedDB bool
		if len(includeHostZones) > 0 {
			specifiedDB = true
		}

		for _, hostData := range route53HostList.HostedZones {
			if specifiedDB {
				if !slices.Contains(includeHostZones, *hostData.Name) {
					continue
				}
				includeHostZones = thisObj.removeFromStringSlice(includeHostZones, fmt.Sprintf("%v", *hostData.Name))
			}
			if slices.Contains(excludeHostZones, *hostData.Name) {
				continue
			}

			temp := &Route53{
				HostedZone: hostData,
				ResourceID: *hostData.Id,
			}
			resultList = append(resultList, temp)
		}
	}
	if len(includeHostZones) > 0 {
		for _, includeResource := range includeHostZones {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in rotue53.", includeResource)})
		}
	}
	return resultList, errorList
}
func (thisObj *AWSAppConnector) GetNetworkFireWallResourceData(includeFireWall, excludeFireWall []string, accountID string) ([]*NetworkFirewall, []ErrorVO) {
	resultList := make([]*NetworkFirewall, 0)
	var networkFirewallList *networkfirewall.ListFirewallsOutput
	var errorList []ErrorVO
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := networkfirewall.New(sess)
		networkFirewallList, err = svc.ListFirewalls(nil)
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		var specifiedDB bool
		if len(includeFireWall) > 0 {
			specifiedDB = true
		}

		for _, firewallMetaData := range networkFirewallList.Firewalls {
			if specifiedDB {
				if !slices.Contains(includeFireWall, *firewallMetaData.FirewallName) {
					continue
				}
				includeFireWall = thisObj.removeFromStringSlice(includeFireWall, fmt.Sprintf("%v", *firewallMetaData.FirewallName))
			}
			if slices.Contains(excludeFireWall, *firewallMetaData.FirewallName) {
				continue
			}
			temp := &NetworkFirewall{
				FirewallMetadata: firewallMetaData,
				ResourceID:       *firewallMetaData.FirewallName,
			}
			resultList = append(resultList, temp)
		}
	}
	if len(includeFireWall) > 0 {
		for _, includeResource := range includeFireWall {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in network firewall.", includeResource)})
		}
	}
	return resultList, errorList
}
func (thisObj *AWSAppConnector) GetCloudTrailResourceData(includeTrails, excludeTrails []string, accountID string) ([]*CloudTrail, []ErrorVO) {
	resultList := make([]*CloudTrail, 0)

	var errorList []ErrorVO
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := cloudtrail.New(sess)
		cloudTrailList, err := svc.DescribeTrails(nil)
		if err != nil {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		var specifiedDB bool
		if len(includeTrails) > 0 {
			specifiedDB = true
		}

		for _, trail := range cloudTrailList.TrailList {
			if specifiedDB {
				if !slices.Contains(includeTrails, *trail.Name) {
					continue
				}
				includeTrails = thisObj.removeFromStringSlice(includeTrails, fmt.Sprintf("%v", *trail.Name))
			}

			if slices.Contains(excludeTrails, *trail.Name) {
				continue
			}
			temp := &CloudTrail{
				Trail:      trail,
				ResourceID: *trail.Name,
			}
			resultList = append(resultList, temp)
		}
	}
	if len(includeTrails) > 0 {
		for _, includeResource := range includeTrails {
			errorList = append(errorList, ErrorVO{Error: fmt.Sprintf("Included resource '%v' does not exist in cloudtrail.", includeResource)})
		}
	}
	return resultList, errorList
}

func (thisObj *AWSAppConnector) GetEc2Vpcs(svc *ec2.EC2, input *ec2.DescribeVpcsInput) ([]*ec2.Vpc, error) {
	var vpcs []*ec2.Vpc
	err := svc.DescribeVpcsPages(input,
		func(page *ec2.DescribeVpcsOutput, lastPage bool) bool {
			vpcs = append(vpcs, page.Vpcs...)
			return true
		})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return nil, errors.New(aerr.Message())
		}
		return nil, err
	}
	return vpcs, nil
}

// https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DescribeTrails.html
func (thisObj *AWSAppConnector) DescribeTrails(input *cloudtrail.DescribeTrailsInput) ([]*cloudtrail.Trail, error) {

	// cloud trail is not region sepecific, hence hardcoded the region with zeroth index
	session, err := thisObj.CreateAWSSession(Options{Region: thisObj.Region[0]})
	if err != nil {
		return nil, err
	}
	cloudTrail := cloudtrail.New(session)
	resp, err := cloudTrail.DescribeTrails(input)
	if err != nil {
		return nil, err
	}
	return resp.TrailList, nil

}

func (thisObj *AWSAppConnector) DescribeCloudTralsBasedOnCriteria(includeCriteria, excludeCriteria string) ([]*cloudtrail.Trail, []ErrorVO) {

	var errorDetails []ErrorVO

	cloudTrails, err := thisObj.DescribeTrails(&cloudtrail.DescribeTrailsInput{})
	if err != nil {
		errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("Error while fetching cloud trail details :: %v", err)})
		return nil, errorDetails
	}

	// Check if criteria exist
	hasIncludeCriteria := cowlibutils.IsNotEmpty(includeCriteria)
	hasExcludeCriteria := cowlibutils.IsNotEmpty(excludeCriteria)

	// No criteria exists, hence no filter
	if !hasIncludeCriteria && !hasExcludeCriteria {
		return cloudTrails, nil
	}

	// Criteria exist
	includeAll := strings.Contains(includeCriteria, "*")
	includeTrails := strings.Split(includeCriteria, ",")
	excludeTrails := strings.Split(excludeCriteria, ",")

	var filteredCloudTrails []*cloudtrail.Trail

	for _, cloudTrail := range cloudTrails {
		cloudTrailName := *cloudTrail.Name

		// Check if cloud trail should be included
		shouldInclude := (hasIncludeCriteria && slices.Contains(includeTrails, cloudTrailName)) || includeAll

		// Check if cloud trail should be excluded
		shouldExclude := hasExcludeCriteria && slices.Contains(excludeTrails, cloudTrailName)

		// Add the cloud trail to the result if it meets the criteria
		if shouldInclude && !shouldExclude {
			filteredCloudTrails = append(filteredCloudTrails, cloudTrail)
		}
	}

	return filteredCloudTrails, nil
}

// https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DescribeLogGroups.html
func (thisObj *AWSAppConnector) DescribeLogGroups(input *cloudwatchlogs.DescribeLogGroupsInput) ([]*cloudwatchlogs.LogGroup, []ErrorVO) {

	var logGroups []*cloudwatchlogs.LogGroup
	var errorDetails []ErrorVO
	for _, region := range thisObj.Region {
		var regionBasedLogGrps []*cloudwatchlogs.LogGroup
		session, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		cloudWatchLogs := cloudwatchlogs.New(session)
		for {
			logGroup, err := cloudWatchLogs.DescribeLogGroups(input)
			if err != nil {
				errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("Region: %v ; Error while fetching logGroup details: %v", region, err.Error())})
				break
			}
			// collecting logGroups in a specified region
			regionBasedLogGrps = append(regionBasedLogGrps, logGroup.LogGroups...)
			if logGroup.NextToken == nil || *logGroup.NextToken == "" {
				break
			}
			input.SetNextToken(*logGroup.NextToken)
		}
		if len(regionBasedLogGrps) > 0 {
			// attaching region specified logGroups to the logGroup result
			logGroups = append(logGroups, regionBasedLogGrps...)
		} else {
			// if there is no logGroups in the specified region
			errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, "No logGroups found in the specified region")})
		}

	}
	return logGroups, errorDetails
}

func (thisObj *AWSAppConnector) DescribeLogGroupsBasedOnCriteria(includeCriteria, excludeCriteria string) ([]*cloudwatchlogs.LogGroup, []ErrorVO) {
	logGroups, errorList := thisObj.DescribeLogGroups(&cloudwatchlogs.DescribeLogGroupsInput{})
	if errorList != nil {
		return nil, errorList
	}

	// Check if criteria exist
	hasIncludeCriteria := cowlibutils.IsNotEmpty(includeCriteria)
	hasExcludeCriteria := cowlibutils.IsNotEmpty(excludeCriteria)

	// No criteria exists, hence no filter
	if !hasIncludeCriteria && !hasExcludeCriteria {
		return logGroups, nil
	}

	// Criteria exist
	includeAll := strings.Contains(includeCriteria, "*")
	includeLogGroups := strings.Split(includeCriteria, ",")
	excludeLogGroups := strings.Split(excludeCriteria, ",")

	var filteredLogGroups []*cloudwatchlogs.LogGroup

	for _, logGroup := range logGroups {
		logGroupName := *logGroup.LogGroupName

		// Check if log group should be included
		shouldInclude := (hasIncludeCriteria && slices.Contains(includeLogGroups, logGroupName)) || includeAll

		// Check if log group should be excluded
		shouldExclude := hasExcludeCriteria && slices.Contains(excludeLogGroups, logGroupName)

		// Add the log group to the result if it meets the criteria
		if shouldInclude && !shouldExclude {
			filteredLogGroups = append(filteredLogGroups, logGroup)
		}
	}

	return filteredLogGroups, nil
}

// https://docs.aws.amazon.com/aws-backup/latest/devguide/API_ListRecoveryPointsByBackupVault.html
func (thisObj *AWSAppConnector) ListBackupVaults(input *backup.ListBackupVaultsInput) (backUpVaults []*backup.VaultListMember, errorDetails []ErrorVO) {
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, err.Error())})
			continue
		}
		svc := backup.New(sess)
		err = svc.ListBackupVaultsPages(input, func(page *backup.ListBackupVaultsOutput, lastPage bool) bool {
			backUpVaults = append(backUpVaults, page.BackupVaultList...)
			return true
		})

		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("Region: %v ; %v", region, aerr.Error())})
			} else {
				errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("Region: %v ;Error while fetching backUpVault details: %v", region, err.Error())})
			}
		}
	}
	return backUpVaults, errorDetails
}

// https://docs.aws.amazon.com/aws-backup/latest/devguide/API_ListRecoveryPointsByBackupVault.html
func (thisObj *AWSAppConnector) ListRecoveryPointsByBackupVault(input *backup.ListRecoveryPointsByBackupVaultInput, region string) (recoveryPointByBackupVaults []*backup.RecoveryPointByBackupVault, errorDetails []ErrorVO) {

	var errMsg string
	session, err := thisObj.CreateAWSSession(Options{Region: region})
	if err != nil {
		errMsg = fmt.Sprintf("Error while creating session: %v", err)
		errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, errMsg)})
		return nil, errorDetails
	}

	backUpVaultsClient := backup.New(session)
	for {
		recoveryPointByBackupVault, err := backUpVaultsClient.ListRecoveryPointsByBackupVault(input)
		if err != nil {
			errMsg = fmt.Sprintf("Error while fetching RecoveryPoint details for BackupVaultName %v in %v: %v", *input.BackupVaultName, region, err)
			errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("Region: %v ;%v", region, errMsg)})
			continue
		}
		if len(recoveryPointByBackupVault.RecoveryPoints) != 0 {
			recoveryPointByBackupVaults = append(recoveryPointByBackupVaults, recoveryPointByBackupVault.RecoveryPoints...)
		}
		if recoveryPointByBackupVault.NextToken == nil || *recoveryPointByBackupVault.NextToken == "" {
			break
		}
		input.SetNextToken(*recoveryPointByBackupVault.NextToken)
	}

	return recoveryPointByBackupVaults, nil
}

// https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUsers.html
func (thisObj *AWSAppConnector) ListUsers(input *iam.ListUsersInput) ([]*iam.User, []ErrorVO) {

	var listUsersOutputlist []*iam.User
	var errorDetails []ErrorVO
	var marker *string
	var errMsg string
	session, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		errMsg = fmt.Sprintf("Error while creating session: %v", err)
		errorDetails = append(errorDetails, ErrorVO{Error: errMsg})
		return nil, errorDetails
	}
	iamClient := iam.New(session)
	for {
		input.Marker = marker
		resp, err := iamClient.ListUsers(input)
		if err != nil {
			errMsg = fmt.Sprintf("Error while fetching userLists : %v", err)
			errorDetails = append(errorDetails, ErrorVO{Error: errMsg})
			break
		}
		if resp != nil {
			listUsersOutputlist = append(listUsersOutputlist, resp.Users...)
		}
		if !*resp.IsTruncated {
			break
		}
		marker = resp.Marker
	}
	return listUsersOutputlist, errorDetails

}

// https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListGroupsForUser.html
func (thisObj *AWSAppConnector) ListGroupsForUser(input *iam.ListGroupsForUserInput) ([]*iam.Group, []ErrorVO) {

	var output []*iam.Group
	var errorDetails []ErrorVO
	var marker *string
	var errMsg string

	// hardcode region with with zeroth index to avoid duplication since IAM users are not region specific
	session, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		errMsg = fmt.Sprintf("Error while creating session: %v", err)
		errorDetails = append(errorDetails, ErrorVO{Error: errMsg})
		return nil, errorDetails
	}
	iamClient := iam.New(session)

	for {
		input.Marker = marker
		resp, err := iamClient.ListGroupsForUser(input)
		if err != nil {
			errMsg = fmt.Sprintf("Error fetching groups for user: %v-%v", *input.UserName, err)
			errorDetails = append(errorDetails, ErrorVO{Error: errMsg})
			break
		}
		if resp != nil {
			output = append(output, resp.Groups...)
		}
		if !*resp.IsTruncated {
			break
		}
		marker = resp.Marker
	}
	return output, errorDetails
}

// https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetUser.html
func (thisObj *AWSAppConnector) GetUser(input *iam.GetUserInput) (*iam.User, ErrorVO) {
	var errorDetails ErrorVO
	var errMsg string

	session, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		errorDetails = ErrorVO{Error: err.Error()}
		return nil, errorDetails
	}

	iamClient := iam.New(session)

	userData, err := iamClient.GetUser(input)
	if err != nil {
		errMsg = fmt.Sprintf("Error while fetching user details for the user: %v :: %v", *input.UserName, err)
		errorDetails = ErrorVO{Error: errMsg}
		return nil, errorDetails
	}
	return userData.User, errorDetails

}

// GetUsers - array contains user details fetched from getuser
func (thisObj *AWSAppConnector) GetUsers(input *iam.ListUsersInput) ([]*iam.User, []ErrorVO) {

	var users []*iam.User
	var combinedErrors []ErrorVO
	userList, errorDetail := thisObj.ListUsers(input)
	if errorDetail != nil {
		return nil, errorDetail
	}
	for _, user := range userList {
		// fetching userDetails from GetUser
		userDetails, err := thisObj.GetUser(&iam.GetUserInput{UserName: user.UserName})
		if cowlibutils.IsNotEmpty(err.Error) {
			combinedErrors = append(combinedErrors, err)
			continue
		}
		users = append(users, userDetails)
	}
	return users, combinedErrors
}

func (thisObj *AWSAppConnector) DescribeConfigRules(ruleset *configservice.DescribeConfigRulesInput, region string) ([]*configservice.ConfigRule, ErrorVO) {

	var outputConfigRules []*configservice.ConfigRule
	var errorDetails ErrorVO

	session, err := thisObj.CreateAWSSession(Options{Region: region})
	if err != nil {
		errorDetails.Error = fmt.Sprintf("Region: %v ;Error while creating session: %v", region, err)
		return nil, errorDetails
	}
	configserviceClient := configservice.New(session)
	configrulesoutput, err := configserviceClient.DescribeConfigRules(ruleset)
	if err != nil {
		errorDetails.Error = fmt.Sprintf("Region: %v ;Error while fetching rules: %v", region, err)
		return nil, errorDetails
	}
	outputConfigRules = append(outputConfigRules, configrulesoutput.ConfigRules...)
	if configrulesoutput.NextToken != nil {
		ruleset := &configservice.DescribeConfigRulesInput{}
		ruleset.SetNextToken(*configrulesoutput.NextToken)
		outputRuleSlice, err := thisObj.DescribeConfigRules(ruleset, region)
		if err.Error != "" {
			return nil, err
		}
		outputConfigRules = append(outputConfigRules, outputRuleSlice...)
	}

	return outputConfigRules, errorDetails
}

func (thisObj *AWSAppConnector) GetConfigRuleEvaluationFunc(ruleset *configservice.GetComplianceDetailsByConfigRuleInput, region string) ([]*configservice.EvaluationResult, ErrorVO) {

	var outputEvaluationResult []*configservice.EvaluationResult
	var errorDetails ErrorVO

	session, err := thisObj.CreateAWSSession(Options{Region: region})
	if err != nil {
		errorDetails.Error = fmt.Sprintf("Error while creating session: %v", err)
		return nil, errorDetails
	}
	configserviceClient := configservice.New(session)
	outputRuleEvaluationDetail, err := configserviceClient.GetComplianceDetailsByConfigRule(ruleset)
	if err != nil {
		errorDetails.Error = fmt.Sprintf("Error while fetching config rules: %v", err)
		return nil, errorDetails
	}
	outputEvaluationResult = append(outputEvaluationResult, outputRuleEvaluationDetail.EvaluationResults...)
	if outputRuleEvaluationDetail.NextToken != nil {
		ruleset.SetNextToken(*outputRuleEvaluationDetail.NextToken)
		outputRuleSlice, err := thisObj.GetConfigRuleEvaluationFunc(ruleset, region)
		if err.Error != "" {
			return nil, err
		}
		outputEvaluationResult = append(outputEvaluationResult, outputRuleSlice...)
	}
	return outputEvaluationResult, errorDetails

}

func (thisObj *AWSAppConnector) GetResourceConfiguration(input *configservice.BatchGetResourceConfigInput, region string) (*configservice.BatchGetResourceConfigOutput, error) {

	session, err := thisObj.CreateAWSSession(Options{Region: region})
	if err != nil {
		return nil, fmt.Errorf("error while creating session in %s: %s", region, err.Error())
	}
	configserviceClient := configservice.New(session)
	outputResource, err := configserviceClient.BatchGetResourceConfig(input)
	if err != nil {
		return nil, err
	}
	return outputResource, nil
}

func (thisObj *AWSAppConnector) ListS3Buckets(input *s3.ListBucketsInput) (*s3.ListBucketsOutput, ErrorVO) {

	var errorDetails ErrorVO
	// listing buckets is not region specifc , so hardcoded the region with zeroth index
	session, err := thisObj.CreateAWSSession(Options{Region: thisObj.Region[0]})
	if err != nil {
		errorDetails.Error = fmt.Sprintf("Region: %v ;Error while creating session: %v", thisObj.Region[0], err)
		return nil, errorDetails
	}
	s3Client := s3.New(session)
	// listing all buckets
	bucketLists, err := s3Client.ListBuckets(nil)
	if err != nil {
		errorDetails.Error = fmt.Sprintf("Region: %v ;Error while fecting  bucket details: %v", thisObj.Region[0], err)
		return nil, errorDetails
	}
	return bucketLists, errorDetails

}

func (thisObj *AWSAppConnector) GetBucketLocation(input *s3.GetBucketLocationInput, region string) (*s3.GetBucketLocationOutput, ErrorVO) {

	var errorDetails ErrorVO
	session, err := thisObj.CreateAWSSession(Options{Region: region})
	if err != nil {
		errorDetails.Error = fmt.Sprintf("Region: %v ;Error while creating session: %v", region, err)
		return nil, errorDetails
	}
	s3Client := s3.New(session)
	locationResult, err := s3Client.GetBucketLocation(&s3.GetBucketLocationInput{
		Bucket: input.Bucket,
	})
	if err != nil {
		errorDetails.Error = fmt.Sprintf("Region: %v ;Error while getting bucket location for the bucket: %v", region, err)
		return nil, errorDetails
	}
	return locationResult, errorDetails
}

func (thisObj *AWSAppConnector) GetBucketRegion(input *s3.GetBucketLocationInput) (string, ErrorVO) {
	var bucketRegion string
	var errorDetail ErrorVO
	// getting bucket region does not require a specific region as input. So harcoded zeroth index as region
	bucketLocation, errorDetail := thisObj.GetBucketLocation(input, thisObj.Region[0])
	if errorDetail.Error != "" {
		return "", errorDetail
	}
	if bucketLocation != nil && bucketLocation.LocationConstraint != nil {
		bucketRegion = *bucketLocation.LocationConstraint
	} else if bucketLocation.LocationConstraint == nil && thisObj.Region[0] == "us-east-1" {
		bucketRegion = "us-east-1"
	}
	return bucketRegion, errorDetail
}

func (thisObj *AWSAppConnector) GetS3BukcetLogging(input *s3.GetBucketLoggingInput, region string) (*s3.GetBucketLoggingOutput, ErrorVO) {

	var errorDetails ErrorVO
	session, err := thisObj.CreateAWSSession(Options{Region: region})
	if err != nil {
		errorDetails.Error = fmt.Sprintf("Region: %v ;Error while creating session: %v", region, err)
		return nil, errorDetails
	}
	s3Client := s3.New(session)
	logConfig, err := s3Client.GetBucketLogging(&s3.GetBucketLoggingInput{
		Bucket: input.Bucket,
	})
	if err != nil {
		errorDetails.Error = fmt.Sprintf("Region: %v ;Error while fetching log configuration for bucket: %v", region, err)
		return nil, errorDetails
	}
	return logConfig, errorDetails
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketVersioning.html
func (thisObj *AWSAppConnector) GetBucketVersioning(input *s3.GetBucketVersioningInput, region string) (*s3.GetBucketVersioningOutput, ErrorVO) {

	var errorDetails ErrorVO
	session, err := thisObj.CreateAWSSession(Options{Region: region})
	if err != nil {
		errorDetails.Error = fmt.Sprintf("Region: %v ;Error while creating session: %v", region, err)
		return nil, errorDetails
	}
	s3Client := s3.New(session)
	bucketVersionDetails, err := s3Client.GetBucketVersioning(input)
	if err != nil {
		errMsg := fmt.Sprintf("Error while fetching bucket version details for bucket: %v :: %v", *input.Bucket, err.Error())
		errorDetails.Error = fmt.Sprintf("Region: %v ; %v", region, errMsg)
		return nil, errorDetails
	}
	return bucketVersionDetails, errorDetails
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycle.html
func (thisObj *AWSAppConnector) GetBucketLifecycleConfiguration(input *s3.GetBucketLifecycleConfigurationInput, region string) (*s3.GetBucketLifecycleConfigurationOutput, ErrorVO) {

	var errorDetails ErrorVO
	session, err := thisObj.CreateAWSSession(Options{Region: region})
	if err != nil {
		errorDetails.Error = fmt.Sprintf("Region: %v ;Error while creating session: %v", region, err)
		return nil, errorDetails
	}
	s3Client := s3.New(session)
	lifeCycleDetails, err := s3Client.GetBucketLifecycleConfiguration(input)
	if err != nil {
		errMsg := fmt.Sprintf("Error while fetching bucket life cycle details for bucket: %v :: %v", *input.Bucket, err.Error())
		errorDetails.Error = fmt.Sprintf("Region: %v ;%v", region, errMsg)
		return nil, errorDetails
	}
	return lifeCycleDetails, errorDetails
}

// https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListRoles.html
func (thisObj *AWSAppConnector) ListRoles(input *iam.ListRolesInput) ([]*iam.Role, []ErrorVO) {
	var errorDetails []ErrorVO
	var marker *string
	var output []*iam.Role

	session, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("Error while creating session: %v", err)})
		return nil, errorDetails
	}
	iamClient := iam.New(session)

	for {
		input.Marker = marker
		resp, err := iamClient.ListRoles(input)
		if err != nil {
			errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("Error while fetching roles: %v", err)})
			break
		}
		if resp != nil {
			output = append(output, resp.Roles...)
		}
		if !*resp.IsTruncated {
			break
		}
		marker = resp.Marker
	}
	return output, errorDetails
}

// GetRoles - array contains role details fetched from getRole
func (thisObj *AWSAppConnector) GetRoles(input *iam.ListRolesInput) ([]*iam.Role, []ErrorVO) {

	var roles []*iam.Role
	var combinedErrors []ErrorVO

	roleList, errorDetail := thisObj.ListRoles(input)
	if errorDetail != nil {
		return nil, errorDetail
	}
	for _, role := range roleList {
		roleDetails, err := thisObj.GetRole(&iam.GetRoleInput{RoleName: role.RoleName})
		if err.Error != "" {
			combinedErrors = append(combinedErrors, err)
			continue
		}
		roles = append(roles, roleDetails)
	}
	return roles, combinedErrors
}

// https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetRole.html
func (thisObj *AWSAppConnector) GetRole(input *iam.GetRoleInput) (*iam.Role, ErrorVO) {
	var errorDetails ErrorVO
	var errMsg string

	session, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		errorDetails = ErrorVO{Error: fmt.Sprintf("Error while creating session: %v", err)}
		return nil, errorDetails
	}
	iamClient := iam.New(session)
	resp, err := iamClient.GetRole(input)
	if err != nil {
		errMsg = fmt.Sprintf("Error while fetching user details for the user: %s - %v", *input.RoleName, err)
		errorDetails = ErrorVO{Error: errMsg}
		return nil, errorDetails
	}
	return resp.Role, errorDetails
}

/*
https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAttachedRolePolicies.html
List managed policies
*/
func (thisObj *AWSAppConnector) ListAttachedRolePolicies(input *iam.ListAttachedRolePoliciesInput) ([]string, []ErrorVO) {

	var errorDetails []ErrorVO
	var errMsg string
	var marker *string
	var output []string

	session, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		errMsg = fmt.Sprintf("Error while creating session: %v", err)
		errorDetails = append(errorDetails, ErrorVO{Error: errMsg})
		return nil, errorDetails
	}
	iamClient := iam.New(session)
	for {
		input.Marker = marker
		resp, err := iamClient.ListAttachedRolePolicies(input)
		if err != nil {
			errMsg = fmt.Sprintf("Error while fetching role policies : %v", err)
			errorDetails = append(errorDetails, ErrorVO{Error: errMsg})
			break
		}
		if resp != nil {
			for _, attachedPolicy := range resp.AttachedPolicies {
				output = append(output, *attachedPolicy.PolicyName)
			}
		}
		if !*resp.IsTruncated {
			break
		}
		marker = resp.Marker
	}
	return output, errorDetails

}

/*
https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListRolePolicies.html
List inline policies
*/
func (thisObj *AWSAppConnector) ListRolePolicies(input *iam.ListRolePoliciesInput) ([]string, []ErrorVO) {
	var errorDetails []ErrorVO
	var errMsg string
	var marker *string
	var output []string

	session, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		errMsg = fmt.Sprintf("Error while creating session: %v", err)
		errorDetails = append(errorDetails, ErrorVO{Error: errMsg})
		return nil, errorDetails
	}
	iamClient := iam.New(session)
	for {
		input.Marker = marker
		resp, err := iamClient.ListRolePolicies(input)
		if err != nil {
			errMsg = fmt.Sprintf("Error while fetching inline policy: %v RoleName: %s", err, *input.RoleName)
			errorDetails = append(errorDetails, ErrorVO{Error: errMsg})
			break
		}
		if resp != nil {
			for _, policyName := range resp.PolicyNames {
				output = append(output, *policyName)
			}
		}
		if !*resp.IsTruncated {
			break
		}
		marker = resp.Marker
	}
	return output, errorDetails

}

/*
https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUserPolicies.html
List inline user policies
*/
func (thisObj *AWSAppConnector) ListUserPolicies(input *iam.ListUserPoliciesInput) ([]string, []ErrorVO) {
	var errorDetails []ErrorVO
	var errMsg string
	var marker *string
	var userPolicies []string

	session, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		errMsg = fmt.Sprintf("Error while creating session: %v", err)
		errorDetails = append(errorDetails, ErrorVO{Error: errMsg})
		return nil, errorDetails
	}
	iamClient := iam.New(session)
	for {
		input.Marker = marker
		policies, err := iamClient.ListUserPolicies(input)
		if err != nil {
			errMsg = fmt.Sprintf("Error while fetching inline policy: %v UserName: %s", err, *input.UserName)
			errorDetails = append(errorDetails, ErrorVO{Error: errMsg})
			break
		}
		if policies != nil {
			for _, policyName := range policies.PolicyNames {
				userPolicies = append(userPolicies, *policyName)
			}
		}
		if !*policies.IsTruncated {
			break
		}
		marker = policies.Marker
	}
	return userPolicies, errorDetails

}

// https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListGroups.html
func (thisObj *AWSAppConnector) ListGroups(input *iam.ListGroupsInput) ([]*iam.Group, []ErrorVO) {
	var groups []*iam.Group
	var errorDetails []ErrorVO
	var marker *string
	var errMsg string

	session, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		errMsg = fmt.Sprintf("Error while creating session: %v", err)
		errorDetails = append(errorDetails, ErrorVO{Error: errMsg})
		return nil, errorDetails
	}
	iamClient := iam.New(session)
	for {
		input.Marker = marker
		resp, err := iamClient.ListGroups(input)
		if err != nil {
			errMsg = fmt.Sprintf("Error while fetching groups: %v", err)
			errorDetails = append(errorDetails, ErrorVO{Error: errMsg})
			break
		}
		if resp != nil {
			groups = append(groups, resp.Groups...)
		}
		if !*resp.IsTruncated {
			break
		}
		marker = resp.Marker
	}
	return groups, errorDetails

}

// https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetGroup.html
func (thisObj *AWSAppConnector) GetGroup(input *iam.GetGroupInput) (*iam.Group, ErrorVO) {
	var errorDetails ErrorVO
	var errMsg string

	session, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		errorDetails = ErrorVO{Error: fmt.Sprintf("Error while creating session: %v", err)}
		return nil, errorDetails
	}
	iamClient := iam.New(session)
	resp, err := iamClient.GetGroup(input)
	if err != nil {
		errMsg = fmt.Sprintf("Error while fetching group details: %v", err)
		errorDetails = ErrorVO{Error: errMsg}
		return nil, errorDetails
	}
	return resp.Group, errorDetails
}

// GetGroups - array contains groups details fetched from getGroup
func (thisObj *AWSAppConnector) GetGroups(input *iam.ListGroupsInput) ([]*iam.Group, []ErrorVO) {

	var groups []*iam.Group
	var combinedErrors []ErrorVO
	groupsList, errorDetail := thisObj.ListGroups(input)
	if errorDetail != nil {
		return nil, errorDetail
	}
	for _, group := range groupsList {
		groupDetails, err := thisObj.GetGroup(&iam.GetGroupInput{GroupName: group.GroupName})
		if err.Error != "" {
			combinedErrors = append(combinedErrors, err)
			continue
		}
		groups = append(groups, groupDetails)
	}
	return groups, combinedErrors
}

// https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetGroup.html
func (thisObj *AWSAppConnector) GetGroupUsers(input *iam.GetGroupInput) ([]*iam.User, ErrorVO) {
	var errorDetails ErrorVO
	var errMsg string

	session, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		errorDetails = ErrorVO{Error: fmt.Sprintf("Error while creating session: %v", err)}
		return nil, errorDetails
	}
	iamClient := iam.New(session)
	resp, err := iamClient.GetGroup(input)
	if err != nil {
		errMsg = fmt.Sprintf("Error while fetching group details: %v", err)
		errorDetails = ErrorVO{Error: errMsg}
		return nil, errorDetails
	}
	return resp.Users, errorDetails
}

/*
	    //https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListGroupPolicies.html
		List inline group policies
*/
func (thisObj *AWSAppConnector) ListGroupPolicies(input *iam.ListGroupPoliciesInput) ([]string, []ErrorVO) {
	var errorDetails []ErrorVO
	var errMsg string
	var marker *string
	var output []string

	session, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		errMsg = fmt.Sprintf("Error while creating session: %v", err)
		errorDetails = append(errorDetails, ErrorVO{Error: errMsg})
		return nil, errorDetails
	}
	iamClient := iam.New(session)
	for {
		input.Marker = marker
		resp, err := iamClient.ListGroupPolicies(input)
		if err != nil {
			errMsg = fmt.Sprintf("Error while fetching inline policy: %v Group: %s", err, *input.GroupName)
			errorDetails = append(errorDetails, ErrorVO{Error: errMsg})
			break
		}
		if resp != nil {
			for _, policyName := range resp.PolicyNames {
				output = append(output, *policyName)
			}
		}
		if !*resp.IsTruncated {
			break
		}
		marker = resp.Marker
	}
	return output, errorDetails

}

// https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListMFADevices.html
func (thisObj *AWSAppConnector) ListMFADevices(input *iam.ListMFADevicesInput) ([]*iam.MFADevice, []ErrorVO) {
	var mfaDevices []*iam.MFADevice
	var errorDetails []ErrorVO
	var marker *string
	var errMsg string

	session, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		errMsg = fmt.Sprintf("Error while creating session: %v", err)
		errorDetails = append(errorDetails, ErrorVO{Error: errMsg})
		return nil, errorDetails
	}
	iamClient := iam.New(session)
	for {
		input.Marker = marker
		resp, err := iamClient.ListMFADevices(input)
		if err != nil {
			errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("Error while fetching MFA devices for the user - %v :: %v", *input.UserName, err.Error())})
			return mfaDevices, errorDetails
		}
		if resp != nil {
			mfaDevices = append(mfaDevices, resp.MFADevices...)
		}
		if !*resp.IsTruncated {
			return mfaDevices, nil
		}
		marker = resp.Marker
	}
}

// https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListPolicies.html
func (thisObj *AWSAppConnector) ListPolicies(input *iam.ListPoliciesInput) ([]*iam.Policy, []ErrorVO) {
	var policies []*iam.Policy
	var errorDetails []ErrorVO
	var marker *string

	// policy is not region specific
	session, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("Error while creating session: %v", err)})
		return nil, errorDetails
	}
	iamClient := iam.New(session)
	for {
		input.Marker = marker
		resp, err := iamClient.ListPolicies(input)
		if err != nil {
			errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("Error while fetching policies: %v", err)})
			break
		}
		if resp != nil {
			policies = append(policies, resp.Policies...)
		}
		if !*resp.IsTruncated {
			break
		}
		marker = resp.Marker
	}
	return policies, errorDetails
}

// https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicy.html
func (thisObj *AWSAppConnector) GetPolicy(input *iam.GetPolicyInput) (*iam.Policy, ErrorVO) {
	var errorDetails ErrorVO

	// policy is not region specific
	session, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		errorDetails = ErrorVO{Error: fmt.Sprintf("Error while creating session: %v", err)}
		return nil, errorDetails
	}
	iamClient := iam.New(session)
	resp, err := iamClient.GetPolicy(input)
	if err != nil {
		errorDetails = ErrorVO{Error: fmt.Sprintf("Error while fetching policy detail: %s for policy: %s", err.Error(), *input.PolicyArn)}
		return nil, errorDetails
	}
	return resp.Policy, errorDetails
}

// GetPolicies - array contains policy details fetched from GetPolicy
func (thisObj *AWSAppConnector) GetPolicies(input *iam.ListPoliciesInput) ([]*iam.Policy, []ErrorVO) {

	var policies []*iam.Policy
	var combinedErrors []ErrorVO

	policyList, errorDetail := thisObj.ListPolicies(input)
	if errorDetail != nil {
		return nil, errorDetail
	}
	for _, policy := range policyList {
		// fetching policy details from Get Policy
		policyDetails, err := thisObj.GetPolicy(&iam.GetPolicyInput{PolicyArn: policy.Arn})
		if err.Error != "" {
			combinedErrors = append(combinedErrors, err)
			continue
		}
		policies = append(policies, policyDetails)
	}

	return policies, combinedErrors
}

/*
Fetch policy document in string format. This document is used to fetch statements involved in policy
https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicyVersion.html
*/
func (thisObj *AWSAppConnector) GetPolicyDocumentStr(input *iam.GetPolicyVersionInput) (string, error) {

	// policy is not region specific
	session, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		return "", fmt.Errorf("Error while creating session: %v", err)
	}
	iamClient := iam.New(session)
	policyVersion, err := iamClient.GetPolicyVersion(input)
	if err != nil {
		fmt.Println("Error getting policy version:", err)
		return "", err
	}
	policyDocument := aws.StringValue(policyVersion.PolicyVersion.Document)
	/*
		The policy document returned in structure is URL-encoded compliant with
		RFC 3986 (https://tools.ietf.org/html/rfc3986). You can use a URL decoding
		method to convert the policy back to plain JSON text
	*/
	decodedString, err := url.QueryUnescape(policyDocument)
	if err != nil {
		fmt.Println("Error decoding:", err)
		return "", err
	}
	return decodedString, nil
}

// https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html
func (thisObj *AWSAppConnector) GetAccountAuthorizationDetails(input *iam.GetAccountAuthorizationDetailsInput) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	accAuthDetails := &iam.GetAccountAuthorizationDetailsOutput{}
	sess, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		return nil, err
	}
	svc := iam.New(sess)
	err = svc.GetAccountAuthorizationDetailsPages(input,
		func(page *iam.GetAccountAuthorizationDetailsOutput, lastPage bool) bool {
			accAuthDetails.UserDetailList = append(accAuthDetails.UserDetailList, page.UserDetailList...)
			accAuthDetails.GroupDetailList = append(accAuthDetails.GroupDetailList, page.GroupDetailList...)
			accAuthDetails.RoleDetailList = append(accAuthDetails.RoleDetailList, page.RoleDetailList...)
			accAuthDetails.Policies = append(accAuthDetails.Policies, page.Policies...)
			return true
		})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return nil, errors.New(aerr.Message())
		} else {
			return nil, err
		}
	}
	return accAuthDetails, nil
}

// https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html
func (thisObj *AWSAppConnector) SimulatePrincipalPolicy(input *iam.SimulatePrincipalPolicyInput) (*iam.SimulatePolicyResponse, error) {
	err := input.Validate()
	if err != nil {
		return nil, err
	}
	sess, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		return nil, err
	}
	svc := iam.New(sess)
	response, err := svc.SimulatePrincipalPolicy(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return nil, errors.New(aerr.Message())
		} else {
			return nil, err
		}
	}
	return response, nil
}

// https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetContextKeysForPrincipalPolicy.html
func (thisObj *AWSAppConnector) GetContextKeysForPrincipalPolicy(input *iam.GetContextKeysForPrincipalPolicyInput) (*iam.GetContextKeysForPolicyResponse, error) {
	err := input.Validate()
	if err != nil {
		return nil, err
	}
	sess, err := thisObj.CreateAWSSession(Options{})
	if err != nil {
		return nil, err
	}
	svc := iam.New(sess)
	response, err := svc.GetContextKeysForPrincipalPolicy(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return nil, errors.New(aerr.Message())
		} else {
			return nil, err
		}
	}
	return response, nil
}

func (thisObj *AWSAppConnector) ListAuditManagerFrameworks(input *auditmanager.ListAssessmentFrameworksInput) ([]*auditmanager.AssessmentFrameworkMetadata, error) {
	// Create an AWS Audit Manager client using the provided session

	output := make([]*auditmanager.AssessmentFrameworkMetadata, 0)

	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			return nil, err
		}
		client := auditmanager.New(sess)

		for {
			frameworksOutput, err := client.ListAssessmentFrameworks(input)
			if err != nil {
				return nil, err
			}
			output = append(output, frameworksOutput.FrameworkMetadataList...)

			if frameworksOutput.NextToken == nil || cowlibutils.IsEmpty(*frameworksOutput.NextToken) {
				break
			}
			input.SetNextToken(*frameworksOutput.NextToken)
		}

	}

	return output, nil
}

func (thisObj *AWSAppConnector) ListAuditManagerAssesments(input *auditmanager.ListAssessmentsInput) ([]*auditmanager.AssessmentMetadataItem, error) {
	// Create an AWS Audit Manager client using the provided session

	output := make([]*auditmanager.AssessmentMetadataItem, 0)

	for _, region := range thisObj.Region {

		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			return nil, err
		}
		client := auditmanager.New(sess)
		for {
			assesmentsOutput, err := client.ListAssessments(input)
			if err != nil {
				return nil, err
			}
			if len(assesmentsOutput.AssessmentMetadata) != 0 {
				output = append(output, assesmentsOutput.AssessmentMetadata...)

			}

			if assesmentsOutput.NextToken == nil || cowlibutils.IsEmpty(*assesmentsOutput.NextToken) {
				break
			}
			input.SetNextToken(*assesmentsOutput.NextToken)

		}

	}

	return output, nil
}

func (thisObj *AWSAppConnector) GetAuditManagerAssesmentReport(input *auditmanager.GetAssessmentInput) (*auditmanager.GetAssessmentOutput, error) {
	// Create an AWS Audit Manager client using the provided session

	var assesmentReport *auditmanager.GetAssessmentOutput

	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			return assesmentReport, err
		}
		client := auditmanager.New(sess)

		assesmentReport, err = client.GetAssessment(input)
		if err != nil {
			return assesmentReport, err
		}

	}

	return assesmentReport, nil
}

func (thisObj *AWSAppConnector) GetAuditManagerEvidenceFolder(input *auditmanager.GetEvidenceFoldersByAssessmentInput) ([]*auditmanager.AssessmentEvidenceFolder, error) {
	// Create an AWS Audit Manager client using the provided session

	assesmentReport := make([]*auditmanager.AssessmentEvidenceFolder, 0)
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			return nil, err
		}
		client := auditmanager.New(sess)
		for {

			resp, err := client.GetEvidenceFoldersByAssessment(input)
			if err != nil {
				return nil, err
			}
			if resp != nil && len(resp.EvidenceFolders) != 0 {
				assesmentReport = append(assesmentReport, resp.EvidenceFolders...)
				if resp.NextToken == nil || cowlibutils.IsEmpty(*resp.NextToken) {
					break
				}
			}

			input.SetNextToken(*resp.NextToken)
		}

	}
	return assesmentReport, nil
}

func (inst *AWSAppConnector) CalculateComplianceScore(totalRecord, failedRecord int) (int, string) {
	compliancePCT, complianceStatus := 100, "COMPLIANT"
	if failedRecord > 0 {
		compliancePCT = int(100 - ((failedRecord * 100) / totalRecord))
		complianceStatus = "NON_COMPLIANT"
	}
	if totalRecord == 0 {
		compliancePCT = 0
		complianceStatus = "NOT_DETERMINED"
	}
	return compliancePCT, complianceStatus
}

func (thisObj *AWSAppConnector) ValidateStruct(s interface{}) error {
	validate := validator.New()
	if err := validate.Struct(s); err != nil {
		return err
	}
	return nil
}

func (thisObj *AWSAppConnector) GetCurrentTime() string {
	currentTime := time.Now().UTC()
	formattedTimestamp := currentTime.Format("2006-01-02T15:04:05.999Z")
	return formattedTimestamp
}

func (thisObj *AWSAppConnector) GetResourceUrl(resourceInfo ResourceInfo) (string, error) {
	url, exists := resourceUrlMap[resourceInfo.ResourceType]
	if !exists {
		return "", fmt.Errorf("Invalid resource type name: %v", resourceInfo.ResourceType)
	}
	url, err := thisObj.ModifyUrl(url, resourceInfo)
	if err != nil {
		return "", err
	}
	return url, nil
}
func (thisObj *AWSAppConnector) removeFromStringSlice(arr []string, value string) []string {
	result := []string{}
	for _, v := range arr {
		if v != value {
			result = append(result, v)
		}
	}
	return result
}
func (thisObj *AWSAppConnector) ModifyUrl(url string, resourceInfo ResourceInfo) (string, error) {

	placeholderPattern := `<<([^>]*)>>`
	placeholders := extractPlaceholders(url, placeholderPattern)

	// Check if all url placeholders are present in the input struct
	for _, placeholder := range placeholders {
		if placeholder == REGION && cowlibutils.IsEmpty(resourceInfo.Region) {
			return "", fmt.Errorf("Required placeholder %s not found in input struct", REGION)
		} else if placeholder == RESOURCE && cowlibutils.IsEmpty(resourceInfo.Resource) {
			return "", fmt.Errorf("Required placeholder %s not found in input struct", RESOURCE)
		} else if placeholder == RESOURCE_PARENT && cowlibutils.IsEmpty(resourceInfo.ResourceParent) {
			return "", fmt.Errorf("Required placeholder %s not found in input struct", RESOURCE_PARENT)
		}
	}

	// Replace placeholders in the URL with corresponding values from the input struct
	replacementMap := map[string]string{
		REGION:          resourceInfo.Region,
		RESOURCE:        resourceInfo.Resource,
		RESOURCE_PARENT: resourceInfo.ResourceParent,
	}
	for placeholder, value := range replacementMap {
		url = strings.ReplaceAll(url, placeholder, value)
	}

	return url, nil
}

func extractPlaceholders(input string, pattern string) []string {

	re := regexp.MustCompile(pattern)
	matches := re.FindAllStringSubmatch(input, -1)

	placeholders := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			placeholders = append(placeholders, match[0])
		}
	}
	return placeholders

}

func (thisObj *AWSAppConnector) CreateMetaFileData(data interface{}) MetaFileVO {
	var fieldMetaData MetaFileVO
	val := reflect.ValueOf(data)
	for i := 0; i < val.NumField(); i++ {
		// Skip fields with an empty struct
		if val.Type().Field(i).Type == reflect.TypeOf(struct{}{}) {
			continue
		}
		fieldName := val.Type().Field(i).Name
		columnData := val.Field(i).Interface()
		var columnType string
		switch columnData.(type) {
		case string, *string:
			columnType = "STRING"
		case bool, *bool:
			columnType = "BOOLEAN"
		case int, *int, int8, *int8, int16, *int16, int32, *int32, int64, *int64, uint, *uint, uint8, *uint8, uint16, *uint16, uint32, *uint32, uint64, *uint64:
			columnType = "INTEGER"
		case float32, *float32, float64, *float64:
			columnType = "FLOAT"
		default:
			columnType = "RECORD"
		}
		srcConfigEntry := SrcConfig{
			Mode:                    "NULLABLE",
			Name:                    fieldName,
			Type:                    columnType,
			FieldName:               fieldName,
			FieldDisplayName:        fieldName,
			IsFieldIndexed:          true,
			IsFieldVisible:          true,
			IsFieldVisibleForClient: true,
			CanUpdate:               false,
			IsRequired:              true,
			IsRepeated:              false,
			HtmlElementType:         columnType,
			FieldDataType:           columnType,
			FieldOrder:              i,
		}
		fieldMetaData.SrcConfig = append(fieldMetaData.SrcConfig, srcConfigEntry)
	}
	return fieldMetaData
}

type MetaFileVO struct {
	SrcConfig []SrcConfig
}

type SrcConfig struct {
	Mode                    string
	Name                    string
	Type                    string
	FieldName               string
	FieldDisplayName        string
	IsFieldIndexed          bool
	IsFieldVisible          bool
	IsFieldVisibleForClient bool
	CanUpdate               bool
	IsRequired              bool
	IsRepeated              bool
	HtmlElementType         string
	FieldDataType           string
	FieldOrder              int
}

type BucketDetails struct {
	ResourceName string     `description:"ResourceName"`
	CreationDate *time.Time `type:"timestamp"`
	Region       string     `description:"Region"`
	ResourceID   string     `description:"ResourceID"`
	LogEnabled   bool       `description:"LogEnabled"`
	AccountID    string     `description:"AccountID"`
	TargetBucket string     `description:"TargetBucket"`
	ResourceARN  string     `description:"ResourceARN"`
}

type ResourceInfo struct {
	Region         string `description:"Region"`
	ResourceType   string `description:"ResourceType"`
	ResourceParent string `description:"ResourceParent"`
	Resource       string `description:"Resource"`
}

type TimeStream struct {
	*timestreaminfluxdb.DbInstanceSummary
	ResourceID string
}
type EC2 struct {
	*ec2.Instance
	ResourceID  string
	InstanceARN string
}
type DynamoDB struct {
	*dynamodb.TableDescription
	ResourceID string
}
type ElasticCache struct {
	*elasticache.CacheCluster
	ResourceID string
}
type EC2VPC struct {
	*ec2.Vpc
	ResourceID string
}
type Neptune struct {
	*neptune.DBInstance
	ResourceID string
}
type RDS struct {
	*rds.DBInstance
	ResourceID string
}
type DocDB struct {
	*docdb.DBInstance
	ResourceID string
}
type QLDB struct {
	*qldb.LedgerSummary
	ResourceID string
}
type Keyspaces struct {
	*keyspaces.KeyspaceSummary
	ResourceID string
}
type CloudFront struct {
	*cloudfront.DistributionSummary
	ResourceID string
}
type DirectConnect struct {
	*directconnect.Connection
	ResourceID string
}
type Route53 struct {
	*route53.HostedZone
	ResourceID string
}
type NetworkFirewall struct {
	*networkfirewall.FirewallMetadata
	ResourceID string
}
type CloudTrail struct {
	*cloudtrail.Trail
	ResourceID string
}
type IamUser struct {
	*iam.User
	ResourceID string
}
type IamRole struct {
	*iam.Role
	ResourceID string
}
