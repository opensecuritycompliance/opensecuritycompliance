package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	awsconnector "applicationtypes/awsappconnector"
	storage "applicationtypes/minio"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/google/uuid"
)

// AWSMFAPolicySimulatorReport :
func (inst *TaskInstance) AWSMFAPolicySimulatorReport(inputs *UserInputs, outputs *Outputs) (deferredErr error) {
	errorDetails := ErrorVO{}
	defer func() {
		if errorDetails != (ErrorVO{}) {
			outputs.LogFile, deferredErr = inst.uploadLogFile(errorDetails)
		}
	}()

	err := inst.validateApp()
	if err != nil {
		errorDetails = ErrorVO{Error: err.Error()}
		return nil
	}

	awsConnector := awsconnector.AWSAppConnector{UserDefinedCredentials: &inst.UserObject.App.UserDefinedCredentials}
	err = awsConnector.ValidateStruct(inputs)
	if err != nil {
		errorDetails = ErrorVO{Error: fmt.Sprintf("Failed to validate inputs: %v", err)}
		return nil
	}

	fileContent, err := storage.DownloadFile(inputs.AccountAuthorizationDetails, inst.SystemInputs)
	if err != nil {
		errorMessage := fmt.Sprintf("Failed to download AccountAuthorizationDetails from Minio: %s", err.Error())
		errorDetails = ErrorVO{Error: errorMessage}
		return nil
	}

	accountAuthDetails, err := inst.readAccountAuthorizationDetails(fileContent)
	if err != nil {
		errorDetails = ErrorVO{Error: err.Error()}
		return nil
	}

	mfaRecommendationBytes, err := storage.DownloadFile(inputs.MFARecommendationFile, inst.SystemInputs)
	if err != nil {
		errorMessage := fmt.Sprintf("Failed to download MFARecommendationFile from Minio: %s", err.Error())
		errorDetails = ErrorVO{Error: errorMessage}
		return nil
	}

	mfaRecommendation, err := inst.readMFARecommendationFile(mfaRecommendationBytes)
	if err != nil {
		errorDetails = ErrorVO{Error: err.Error()}
		return nil
	}

	userList, groupList, roleList := inst.getIAMEntities(inputs, accountAuthDetails)

	policySimulatorReport, err := inst.createPolicyReport(awsConnector, userList, groupList, roleList, mfaRecommendation)
	if err != nil {
		errorDetails = ErrorVO{Error: err.Error()}
		return nil
	}

	if len(policySimulatorReport) > 0 {
		outputs.MFAPolicySimulatorReport, err = inst.uploadOutputFile(policySimulatorReport)
		if err != nil {
			errorDetails = ErrorVO{Error: err.Error()}
			return nil
		}
		outputs.MetaFile, err = inst.uploadMetaFile(awsConnector, policySimulatorReport)
		if err != nil {
			errorDetails = ErrorVO{Error: err.Error()}
			return nil
		}
	}

	return deferredErr
}

func (inst *TaskInstance) validateApp() error {
	if inst.UserObject == nil {
		return errors.New("Missing: User object")
	}
	if inst.UserObject.App == nil {
		return errors.New("Missing: App object")
	}
	if inst.UserObject.App.UserDefinedCredentials == (awsconnector.UserDefinedCredentials{}) {
		return errors.New("Missing: User defined credentials")
	}
	return nil
}

func (inst *TaskInstance) readAccountAuthorizationDetails(dataBytes []byte) ([]AccountAuthorizationVO, error) {
	var accAuthDetails []AccountAuthorizationVO
	if err := json.Unmarshal(dataBytes, &accAuthDetails); err != nil {
		return nil, fmt.Errorf("Failed to unmarshal AWS account authorization details: %w", err)
	}
	return accAuthDetails, nil
}

func (inst *TaskInstance) readMFARecommendationFile(dataInBytes []byte) (MFARecommendationVO, error) {
	var mfaRecommendation MFARecommendationVO
	if err := json.Unmarshal(dataInBytes, &mfaRecommendation); err != nil {
		return mfaRecommendation, fmt.Errorf("Failed to unmarshal MFA recommendation details: %w", err)
	}
	return mfaRecommendation, nil
}

/*
getIAMEntities fetches IAM entities (users, groups, and roles) based on the provided UserInputs and account authorization details.
It filters the entities based on the specified criteria (include/exclude) and returns separate lists for users, groups, and roles.
*/
func (inst *TaskInstance) getIAMEntities(inputs *UserInputs, accAuthDetails []AccountAuthorizationVO) ([]UserDetailListVO, []GroupDetailListVO, []RoleDetailListVO) {
	userList, groupList, roleList, flagAll := []UserDetailListVO{}, []GroupDetailListVO{}, []RoleDetailListVO{}, false

	users := strings.Split(inputs.Users, ",")
	groups := strings.Split(inputs.Groups, ",")
	roles := strings.Split(inputs.Roles, ",")

	for _, userInfo := range accAuthDetails[0].UserDetailList {
	uLoop:
		for _, uname := range users {
			if uname == "*" {
				flagAll = true
			}
			switch inputs.UserStatus {
			case "include":
				if (strings.EqualFold(userInfo.UserName, uname)) || flagAll {
					userList = append(userList, userInfo)
				}
			case "exclude":
				if flagAll {
					break uLoop
				}
				if !(strings.EqualFold(userInfo.UserName, uname)) {
					userList = append(userList, userInfo)
				}
			}

		}
	}

	flagAll = false
	for _, groupInfo := range accAuthDetails[0].GroupDetailList {
	gLoop:
		for _, gname := range groups {
			if gname == "*" {
				flagAll = true
			}
			switch inputs.GroupStatus {
			case "include":
				if strings.EqualFold(groupInfo.GroupName, gname) || flagAll {
					groupList = append(groupList, groupInfo)
				}
			case "exclude":
				if flagAll {
					break gLoop
				}
				if !(strings.EqualFold(groupInfo.GroupName, gname)) {
					groupList = append(groupList, groupInfo)
				}
			}
		}
	}

	flagAll = false
	for _, roleInfo := range accAuthDetails[0].RoleDetailList {
	rLoop:
		for _, rname := range roles {
			if rname == "*" {
				flagAll = true
			}
			switch inputs.RoleStatus {
			case "include":
				if (strings.EqualFold(roleInfo.RoleName, rname)) || flagAll {
					roleList = append(roleList, roleInfo)
				}
			case "exclude":
				if flagAll {
					break rLoop
				}
				if !(strings.EqualFold(roleInfo.RoleName, rname)) {
					roleList = append(roleList, roleInfo)
				}
			}
		}
	}
	return userList, groupList, roleList
}

// createPolicyReport calls the evaluatePolicyWithMFAEnforcement method for users, groups, and roles to obtain the AWS policy simulator report for each resource specified in the MFA recommendation file.
func (inst *TaskInstance) createPolicyReport(awsConnector awsconnector.AWSAppConnector, userList []UserDetailListVO, groupList []GroupDetailListVO, roleList []RoleDetailListVO, mfaRecommendation MFARecommendationVO) ([]PolicySimulatorVO, error) {
	var policySimulatorReport []PolicySimulatorVO
	for _, user := range userList {
		report, err := inst.evaluatePolicyWithMFAEnforcement(awsConnector, user.Arn, user.UserName, "AWS::IAM::User", awsconnector.IAM_USER, mfaRecommendation)
		if err != nil {
			return nil, fmt.Errorf("Failed to evaluate the policy simulator for the user %v: %w", user.UserName, err)
		}
		policySimulatorReport = append(policySimulatorReport, report...)
	}
	for _, group := range groupList {
		report, err := inst.evaluatePolicyWithMFAEnforcement(awsConnector, group.Arn, group.GroupName, "AWS::IAM::Group", awsconnector.IAM_GROUP, mfaRecommendation)
		if err != nil {
			return nil, fmt.Errorf("Failed to evaluate the policy simulator for the group %v: %w", group.GroupName, err)
		}
		policySimulatorReport = append(policySimulatorReport, report...)
	}
	for _, role := range roleList {
		report, err := inst.evaluatePolicyWithMFAEnforcement(awsConnector, role.Arn, role.RoleName, "AWS::IAM::Role", awsconnector.IAM_ROLE, mfaRecommendation)
		if err != nil {
			return nil, fmt.Errorf("Failed to evaluate the policy simulator for the role %v: %w", role.RoleName, err)
		}
		policySimulatorReport = append(policySimulatorReport, report...)
	}

	return policySimulatorReport, nil
}

/*
evaluatePolicyWithMFAEnforcement evaluates policies with Multi-Factor Authentication (MFA) enforcement for a given identity (user, group, or role) and resources specified in the MFA recommendation file.
It calls AWS's SimulatePrincipalPolicy to obtain policy evaluation results and GetContextKeysForPrincipalPolicy to check if the "multifactorauthpresent" context key is present.
Based on these evaluations, it generates a standardized policy simulation report.
*/
func (inst *TaskInstance) evaluatePolicyWithMFAEnforcement(awsConnector awsconnector.AWSAppConnector, identityARN, identityName, resourceType, identityType string, mfaRecommendation MFARecommendationVO) ([]PolicySimulatorVO, error) {
	var policySimulatorReport []PolicySimulatorVO
	resourceUrl, err := awsConnector.GetResourceUrl(awsconnector.ResourceInfo{
		Region:       "global",
		ResourceType: identityType,
		Resource:     identityName,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to get resource URL: %v", err)
	}
	for _, mfaInfo := range mfaRecommendation {
		mfaFlag := false
		simulatePolicyInput := &iam.SimulatePrincipalPolicyInput{
			PolicySourceArn: aws.String(identityARN),
			ResourceArns:    aws.StringSlice(strings.Split(mfaInfo.Resource, ",")),
			ActionNames:     aws.StringSlice(strings.Split(mfaInfo.Action, ",")),
			ContextEntries: []*iam.ContextEntry{
				{
					ContextKeyName:   aws.String("aws:MultiFactorAuthPresent"),
					ContextKeyType:   aws.String("boolean"),
					ContextKeyValues: aws.StringSlice([]string{"true"}),
				},
			},
		}
		simulatePolicyResponse, err := awsConnector.SimulatePrincipalPolicy(simulatePolicyInput)
		if err != nil {
			return nil, err
		}

		contextPolicyInput := &iam.GetContextKeysForPrincipalPolicyInput{
			PolicySourceArn: aws.String(identityARN),
		}
		contextPolicyResponse, err := awsConnector.GetContextKeysForPrincipalPolicy(contextPolicyInput)
		if err != nil {
			return nil, err
		}
		for _, ck := range contextPolicyResponse.ContextKeyNames {
			if strings.Contains(strings.ToLower(*ck), "multifactorauthpresent") {
				mfaFlag = true
				break
			}
		}

		for _, op := range simulatePolicyResponse.EvaluationResults {
			validationStatusCode, validationStatusNotes, complianceStatus, complianceStatusReason := "", "", "", ""
			var sourcePolicyInfo []SourcePolicyDetailsVO
			for _, ms := range op.MatchedStatements {
				sourcePolicyInfo = append(sourcePolicyInfo, SourcePolicyDetailsVO{SourcePolicyID: *ms.SourcePolicyId, SourcePolicyType: *ms.SourcePolicyType})
			}
			decision := *op.EvalDecision
			if strings.Contains(strings.ToLower(decision), "allowed") && mfaFlag {
				validationStatusCode = "MFA_E"
				validationStatusNotes = "MFA is enforced"
				complianceStatus = "COMPLIANT"
				complianceStatusReason = "MFA implemented in IAM policy"
			} else if strings.Contains(strings.ToLower(decision), "allowed") && !mfaFlag {
				validationStatusCode = "MFA_NE"
				validationStatusNotes = "MFA is not enforced"
				complianceStatus = "NON_COMPLIANT"
				complianceStatusReason = "Implement MFA check for IAM policy"
			} else if strings.Contains(strings.ToLower(decision), "implicitdeny") {
				validationStatusCode = "ACT_NA"
				validationStatusNotes = "Action not allowed implicitly denied"
				complianceStatus = "COMPLIANT"
				complianceStatusReason = "Action implicitly denied (no matching policy statements)"
			} else if strings.Contains(strings.ToLower(decision), "explicitdeny") {
				validationStatusCode = "ACT_NA"
				validationStatusNotes = "Action not allowed explicitly denied"
				complianceStatus = "COMPLIANT"
				complianceStatusReason = "Action explicitly denied"
			}

			record := PolicySimulatorVO{
				System:                 "aws",
				Source:                 "compliancecow",
				ResourceId:             identityARN,
				ResourceName:           identityName,
				ResourceType:           resourceType,
				ResourceLocation:       "global",
				ResourceURL:            resourceUrl,
				Action:                 *op.EvalActionName,
				ActionResource:         *op.EvalResourceName,
				Decision:               decision,
				MFAPresent:             mfaFlag,
				SourcePolicyDetails:    sourcePolicyInfo,
				ValidationStatusCode:   validationStatusCode,
				ValidationStatusNotes:  validationStatusNotes,
				ComplianceStatus:       complianceStatus,
				ComplianceStatusReason: complianceStatusReason,
				EvaluatedTime:          awsConnector.GetCurrentTime(),
			}
			policySimulatorReport = append(policySimulatorReport, record)
		}
	}
	return policySimulatorReport, nil
}

func (inst *TaskInstance) uploadOutputFile(outputData []PolicySimulatorVO) (string, error) {
	outputFileNameWithUUID := fmt.Sprintf("%v-%v%v", "MFAPolicySimulatorReport", uuid.New().String(), ".json")
	outputFilePath, err := storage.UploadJSONFile(outputFileNameWithUUID, outputData, inst.SystemInputs)
	if err != nil {
		return "", fmt.Errorf("Failed to upload mfa policy simulator report to Minio: %w", err)
	}
	return outputFilePath, nil
}

func (inst *TaskInstance) uploadLogFile(errInfo ErrorVO) (string, error) {
	logFileNameWithUUID := fmt.Sprintf("%v-%v%v", "LogFile", uuid.New().String(), ".json")
	outputFilePath, err := storage.UploadJSONFile(logFileNameWithUUID, errInfo, inst.SystemInputs)
	if err != nil {
		return "", fmt.Errorf("Failed to upload log file to Minio: %w", err)
	}
	return outputFilePath, nil
}

func (inst *TaskInstance) uploadMetaFile(awsConnector awsconnector.AWSAppConnector, outputData []PolicySimulatorVO) (string, error) {
	fieldMetaData := awsConnector.CreateMetaFileData(outputData[0])
	metaFileNameWithUUID := fmt.Sprintf("%v-%v%v", "MetaFile", uuid.New().String(), ".json")
	outputFilePath, err := storage.UploadJSONFile(metaFileNameWithUUID, fieldMetaData, inst.SystemInputs)
	if err != nil {
		return "", fmt.Errorf("Failed to upload policy simulator meta file to Minio: %w", err)
	}
	return outputFilePath, nil
}

type AccountAuthorizationVO struct {
	GroupDetailList []GroupDetailListVO `json:"GroupDetailList"`
	Policies        []PoliciesVO        `json:"Policies"`
	RoleDetailList  []RoleDetailListVO  `json:"RoleDetailList"`
	UserDetailList  []UserDetailListVO  `json:"UserDetailList"`
}

type Tags struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

type UserDetailListVO struct {
	Arn      string `json:"Arn"`
	Path     string `json:"Path"`
	Tags     []Tags `json:"Tags"`
	UserId   string `json:"UserId"`
	UserName string `json:"UserName"`
}

type GroupDetailListVO struct {
	Arn       string `json:"Arn"`
	GroupId   string `json:"GroupId"`
	GroupName string `json:"GroupName"`
	Path      string `json:"Path"`
}

type PoliciesVO struct {
	Arn        string `json:"Arn"`
	Path       string `json:"Path"`
	PolicyId   string `json:"PolicyId"`
	PolicyName string `json:"PolicyName"`
}

type RoleDetailListVO struct {
	Arn      string `json:"Arn"`
	Path     string `json:"Path"`
	Tags     []Tags `json:"Tags"`
	RoleId   string `json:"RoleId"`
	RoleName string `json:"RoleName"`
}

type ErrorVO struct {
	Error string `json:"Error"`
}

type PolicySimulatorVO struct {
	System                 string                  `json:"System"`
	Source                 string                  `json:"Source"`
	ResourceId             string                  `json:"ResourceID"`
	ResourceName           string                  `json:"ResourceName"`
	ResourceType           string                  `json:"ResourceType"`
	ResourceLocation       string                  `json:"ResourceLocation"`
	ResourceTags           interface{}             `json:"ResourceTags"`
	ResourceURL            string                  `json:"ResourceURL"`
	Action                 string                  `json:"Action"`
	ActionResource         string                  `json:"ActionResource"`
	Decision               string                  `json:"Decision"`
	MFAPresent             bool                    `json:"MFAPresent"`
	SourcePolicyDetails    []SourcePolicyDetailsVO `json:"SourcePolicyDetails"`
	ValidationStatusCode   string                  `json:"ValidationStatusCode"`
	ValidationStatusNotes  string                  `json:"ValidationStatusNotes"`
	ComplianceStatus       string                  `json:"ComplianceStatus"`
	ComplianceStatusReason string                  `json:"ComplianceStatusReason"`
	EvaluatedTime          string                  `json:"EvaluatedTime"`
	UserAction             string                  `json:"UserAction"`
	ActionStatus           string                  `json:"ActionStatus"`
	ActionResponseURL      string                  `json:"ActionResponseURL"`
}

type SourcePolicyDetailsVO struct {
	SourcePolicyID   string `json:"SourcePolicyID"`
	SourcePolicyType string `json:"SourcePolicyType"`
}

type MFARecommendationVO []struct {
	Action   string `json:"Action"`
	Resource string `json:"Resource"`
}
