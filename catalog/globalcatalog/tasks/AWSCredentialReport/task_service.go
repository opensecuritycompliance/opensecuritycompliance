package main

import (
	awsconnector "appconnections/awsappconnector"
	storage "appconnections/minio"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/gocarina/gocsv"
	"github.com/google/uuid"
	"golang.org/x/exp/slices"
)

const (
	ZERO           = 0
	NOT_APPLICABLE = "N/A"
)

// AWSCredentialReport :
func (inst *TaskInstance) AWSCredentialReport(inputs *UserInputs, outputs *Outputs) (deferr error) {
	errorDetails := &[]ErrorVO{}
	defer func() {
		if len(*errorDetails) > 0 {
			outputs.LogFile, deferr = inst.uploadLogFile(errorDetails)
		}
	}()

	// validating user object for aws connector creation
	errorVO := inst.validateApp()
	if errorVO != nil {
		*errorDetails = append(*errorDetails, *errorVO)
	}

	awsConnector := awsconnector.AWSAppConnector{UserDefinedCredentials: &inst.UserObject.App.UserDefinedCredentials}
	credentialReportData, err := awsConnector.GetCredentialReport(&iam.GetCredentialReportInput{})
	if err != nil {
		*errorDetails = append(*errorDetails, ErrorVO{ErrorMessage: err.Error()})
		return nil
	}

	var awsCredentialReport []AWSCredentialReportVO
	err = gocsv.UnmarshalBytes(credentialReportData.Content, &awsCredentialReport)
	if err != nil {
		*errorDetails = append(*errorDetails, ErrorVO{ErrorMessage: fmt.Sprintf("Error while unamrshalling credential report :%v", err.Error())})
		return nil
	}
	if len(awsCredentialReport) > ZERO {
		processedCredentialReport, processedErrorDetails := inst.processCredentialReport(awsCredentialReport, awsConnector)
		for _, processedErrorDetail := range processedErrorDetails {
			*errorDetails = append(*errorDetails, ErrorVO{ErrorMessage: processedErrorDetail.Error})
			return nil
		}
		if len(processedCredentialReport) > ZERO {
			outputs.AWSCredentialReport, err = inst.uploadOutputFile(processedCredentialReport)
			if err != nil {
				*errorDetails = append(*errorDetails, ErrorVO{ErrorMessage: err.Error()})
				return nil
			}
		}
	} else {
		*errorDetails = append(*errorDetails, ErrorVO{ErrorMessage: "No users for this AWS account"})
		return nil
	}

	return deferr
}

func (inst *TaskInstance) validateApp() *ErrorVO {
	if inst.UserObject == nil {
		return &ErrorVO{ErrorMessage: "User object is missing."}
	}
	if inst.UserObject.App == nil {
		return &ErrorVO{ErrorMessage: "Application detail is missing."}
	}
	if inst.UserObject.App.UserDefinedCredentials == (awsconnector.UserDefinedCredentials{}) {
		return &ErrorVO{ErrorMessage: "User defined credentials is missing."}
	}
	return nil
}

func (inst *TaskInstance) processCredentialReport(credReport []AWSCredentialReportVO, awsConnector awsconnector.AWSAppConnector) ([]AWSCredentialReportVO, []awsconnector.ErrorVO) {
	var combinedErrors []awsconnector.ErrorVO
	for index, user := range credReport {
		userName := user.User
		isRootAccount := (userName == "<root_account>")
		// If it's a root account, trim the "<>" from the username. By default, the username of the root account will be "<root_account>".
		if isRootAccount {
			userName = strings.Trim(userName, "<>")
			user.User = userName
		}
		inst.normalizeFieldIfNotSupported(&user)
		credReport[index] = user
		/*
		  Fetch MFA devices for non-root accounts.
		  MFA device details of the root account can only be fetched by the root user. So ignoring root account
		*/
		if !isRootAccount {
			mfaDevices, errorDetails := awsConnector.ListMFADevices(&iam.ListMFADevicesInput{UserName: &user.User})
			if errorDetails != nil {
				combinedErrors = append(combinedErrors, errorDetails...)
				continue
			}
			credReport[index].MFADevices = mfaDevices
		}
	}
	return credReport, combinedErrors
}

func (inst *TaskInstance) normalizeFieldIfNotSupported(user *AWSCredentialReportVO) *AWSCredentialReportVO {
	// slice of pointers to the fields that need to be checked and updated
	fields := []*string{
		&user.PasswordEnabled,
		&user.PasswordLastUsed,
		&user.PasswordLastChanged,
		&user.PasswordNextRotation,
		&user.AccessKey1LastRotated,
		&user.Accesskey1LastUsedDate,
		&user.AccessKey2LastRotated,
		&user.Accesskey2LastUsedDate,
		&user.Cert1LastRotated,
		&user.Cert2LastRotated,
	}
	value := []string{"not_supported", "no_information"}
	for _, field := range fields {
		if slices.Contains(value, *field) {
			*field = NOT_APPLICABLE
		}
	}
	return user
}

func (inst *TaskInstance) uploadOutputFile(outputData []AWSCredentialReportVO) (string, error) {
	reportFileNameWithUUID := fmt.Sprintf("%v-%v%v", "AWSCredentialReport", uuid.New().String(), ".json")
	outputFilePath, err := storage.UploadJSONFile(reportFileNameWithUUID, outputData, inst.SystemInputs)
	if err != nil {
		return "", fmt.Errorf("Cannot upload aws credential data to minio: %w", err)
	}
	return outputFilePath, nil
}

func (inst *TaskInstance) uploadLogFile(errorList interface{}) (string, error) {
	auditFileNameWithUUID := fmt.Sprintf("%v-%v%v", "LogFile", uuid.New().String(), ".json")
	outputFilePath, err := storage.UploadJSONFile(auditFileNameWithUUID, errorList, inst.SystemInputs)
	if err != nil {
		return "", fmt.Errorf("Cannot upload audit file to minio: %w", err)
	}
	return outputFilePath, nil
}

type AWSCredentialReportVO struct {
	User                      string           `json:"User" csv:"user"`
	ARN                       string           `json:"ARN" csv:"arn"`
	UserCreationTime          string           `json:"UserCreationTime" csv:"user_creation_time"`
	PasswordEnabled           string           `json:"PasswordEnabled" csv:"password_enabled"`
	PasswordLastUsed          string           `json:"PasswordLastUsed" csv:"password_last_used"`
	PasswordLastChanged       string           `json:"PasswordLastChanged" csv:"password_last_changed"`
	PasswordNextRotation      string           `json:"PasswordNextRotation" csv:"password_next_rotation"`
	MFAActive                 string           `json:"MFAActive" csv:"mfa_active"`
	AccessKey1Active          string           `json:"AccessKey1Active" csv:"access_key_1_active"`
	AccessKey1LastRotated     string           `json:"AccessKey1LastRotated" csv:"access_key_1_last_rotated"`
	Accesskey1LastUsedDate    string           `json:"Accesskey1LastUsedDate" csv:"access_key_1_last_used_date"`
	AccessKey1LastUsedRegion  string           `json:"AccessKey1LastUsedRegion" csv:"access_key_1_last_used_region"`
	AccessKey1LastUsedService string           `json:"AccessKey1LastUsedService" csv:"access_key_1_last_used_service"`
	AccessKey2Active          string           `json:"AccessKey2Active" csv:"access_key_2_active"`
	AccessKey2LastRotated     string           `json:"AccessKey2LastRotated" csv:"access_key_2_last_rotated"`
	Accesskey2LastUsedDate    string           `json:"Accesskey2LastUsedDate" csv:"access_key_2_last_used_date"`
	AccessKey2LastUsedRegion  string           `json:"AccessKey2LastUsedRegion" csv:"access_key_2_last_used_region"`
	AccessKey2LastUsedService string           `json:"AccessKey2LastUsedService" csv:"access_key_2_last_used_service"`
	Cert1Active               string           `json:"Cert1Active" csv:"cert_1_active"`
	Cert1LastRotated          string           `json:"Cert1LastRotated" csv:"cert_1_last_rotated"`
	Cert2Active               string           `json:"Cert2Active" csv:"cert_2_active"`
	Cert2LastRotated          string           `json:"Cert2LastRotated" csv:"cert_2_last_rotated"`
	MFADevices                []*iam.MFADevice `json:"MFADevices"`
}

type ErrorVO struct {
	ErrorMessage string `json:"ErrorMessage"`
}
