package awsappconnector

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	cowlibutils "cowlibrary/utils"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/backup"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/aws/aws-sdk-go/service/sts"
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

type AWSAppConnector struct {
	AppURL                 string                  `json:"appURL" yaml:"url"`
	AppPort                int                     `json:"appPort" yaml:"port"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
	Region                 []string                `json:"region" yaml:"Region"`
}

type ErrorVO struct {
	Region string `json:"Region,omitempty"`
	Error  string `json:"Error"`
}

type Options struct {
	Region string
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

func (thisObj *AWSAppConnector) Validate() (bool, error) {
	if !thisObj.IsEmptyAWSRole() {
		return thisObj.ValidateAWSRole()
	} else if !thisObj.IsEmptyAWSIAM() {
		return thisObj.ValidateAWSIAM()
	}
	return false, fmt.Errorf("not a valid input")
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
			return nil, errors.New(aerr.Message())
		}
		return nil, err
	}
	stsSess, err := session.NewSession(&aws.Config{
		Region:      aws.String(options.Region),
		Credentials: credentials.NewStaticCredentials(*assumeRoleOutput.Credentials.AccessKeyId, *assumeRoleOutput.Credentials.SecretAccessKey, *assumeRoleOutput.Credentials.SessionToken)})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return nil, errors.New(aerr.Message())
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

func (thisObj *AWSAppConnector) IsEmptyAWSIAM() bool {
	iamCreds := thisObj.UserDefinedCredentials.AWSIAM
	return cowlibutils.IsEmpty(iamCreds.AccessKey) || cowlibutils.IsEmpty(iamCreds.SecretKey)
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
			return false, errors.New(aerr.Message())
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
		return nil, fmt.Errorf("not a valid application")
	}
	return sess, nil
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

// https://docs.aws.amazon.com/aws-backup/latest/devguide/API_ListRecoveryPointsByBackupVault.html
func (thisObj *AWSAppConnector) ListBackupVaults(input *backup.ListBackupVaultsInput) (backUpVaults []*backup.VaultListMember, errorDetails []ErrorVO) {
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorDetails = append(errorDetails, ErrorVO{Region: region, Error: fmt.Sprintf("error while creating session: %v", err)})
			continue
		}
		svc := backup.New(sess)
		err = svc.ListBackupVaultsPages(input, func(page *backup.ListBackupVaultsOutput, lastPage bool) bool {
			backUpVaults = append(backUpVaults, page.BackupVaultList...)
			return true
		})

		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				errorDetails = append(errorDetails, ErrorVO{Region: region, Error: aerr.Message()})
			} else {
				errorDetails = append(errorDetails, ErrorVO{Region: region, Error: fmt.Sprintf("error while fetching backUpVault details: %v", err)})
			}
		}
	}
	return backUpVaults, errorDetails
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

// https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DescribeLogGroups.html
func (thisObj *AWSAppConnector) DescribeLogGroups(input *cloudwatchlogs.DescribeLogGroupsInput) ([]*cloudwatchlogs.LogGroup, []ErrorVO) {

	var logGroups []*cloudwatchlogs.LogGroup
	var errorDetails []ErrorVO
	for _, region := range thisObj.Region {
		var regionBasedLogGrps []*cloudwatchlogs.LogGroup
		session, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorDetails = append(errorDetails, ErrorVO{Region: region, Error: err.Error()})
			continue
		}
		cloudWatchLogs := cloudwatchlogs.New(session)
		for {
			logGroup, err := cloudWatchLogs.DescribeLogGroups(input)
			if err != nil {
				errorDetails = append(errorDetails, ErrorVO{Region: region, Error: fmt.Sprintf("Error while fetching logGroup details: %v", err)})
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
			errorDetails = append(errorDetails, ErrorVO{Region: region, Error: "No logGroups in the specified region"})
		}

	}
	return logGroups, errorDetails
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
			errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("error while fetching MFA devices for the user - %v :: %v", *input.UserName, err.Error())})
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

// https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html
func (thisObj *AWSAppConnector) GetSecurityHubFindings(input *securityhub.GetFindingsInput) ([]*securityhub.AwsSecurityFinding, []ErrorVO) {
	var findings []*securityhub.AwsSecurityFinding
	var errorList []ErrorVO
	for _, region := range thisObj.Region {
		sess, err := thisObj.CreateAWSSession(Options{Region: region})
		if err != nil {
			errorList = append(errorList, ErrorVO{Region: region, Error: err.Error()})
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
				errorList = append(errorList, ErrorVO{Region: region, Error: aerr.Message()})
			} else {
				errorList = append(errorList, ErrorVO{Region: region, Error: err.Error()})
			}
			continue
		}
	}
	return findings, errorList
}

func (thisObj *AWSAppConnector) DescribeConfigRules(ruleset *configservice.DescribeConfigRulesInput, region string) ([]*configservice.ConfigRule, ErrorVO) {

	var outputConfigRules []*configservice.ConfigRule
	var errorDetails ErrorVO

	session, err := thisObj.CreateAWSSession(Options{Region: region})
	if err != nil {
		errorDetails.Error = fmt.Sprintf("Error while creating session: %v", err)
		errorDetails.Region = region
		return nil, errorDetails
	}
	configserviceClient := configservice.New(session)
	configrulesoutput, err := configserviceClient.DescribeConfigRules(ruleset)
	if err != nil {
		errorDetails.Error = fmt.Sprintf("Error while fetching rules: %v", err)
		errorDetails.Region = region
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
		errorDetails.Region = region
		return nil, errorDetails
	}
	configserviceClient := configservice.New(session)
	outputRuleEvaluationDetail, err := configserviceClient.GetComplianceDetailsByConfigRule(ruleset)
	if err != nil {
		errorDetails.Error = fmt.Sprintf("Error while fetching config rules: %v", err)
		errorDetails.Region = region
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
		return "", fmt.Errorf("invalid resource type name: %v", resourceInfo.ResourceType)
	}
	url, err := thisObj.ModifyUrl(url, resourceInfo)
	if err != nil {
		return "", err
	}
	return url, nil
}

func (thisObj *AWSAppConnector) ModifyUrl(url string, resourceInfo ResourceInfo) (string, error) {

	placeholderPattern := `<<([^>]*)>>`
	placeholders := extractPlaceholders(url, placeholderPattern)

	// Check if all url placeholders are present in the input struct
	for _, placeholder := range placeholders {
		if placeholder == REGION && cowlibutils.IsEmpty(resourceInfo.Region) {
			return "", fmt.Errorf("required placeholder %s not found in input struct", REGION)
		} else if placeholder == RESOURCE && cowlibutils.IsEmpty(resourceInfo.Resource) {
			return "", fmt.Errorf("required placeholder %s not found in input struct", RESOURCE)
		} else if placeholder == RESOURCE_PARENT && cowlibutils.IsEmpty(resourceInfo.ResourceParent) {
			return "", fmt.Errorf("required placeholder %s not found in input struct", RESOURCE_PARENT)
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

type ResourceInfo struct {
	Region         string `description:"Region"`
	ResourceType   string `description:"ResourceType"`
	ResourceParent string `description:"ResourceParent"`
	Resource       string `description:"Resource"`
}
