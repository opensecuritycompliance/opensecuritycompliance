package main

import (
	awsconnector "applicationtypes/awsappconnector"
	storage "applicationtypes/minio"
	cowlibutils "cowlibrary/utils"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	ZERO           = 0
	NOT_APPLICABLE = "N/A"
	NON_COMPLIANT  = "NON_COMPLIANT"
	COMPLIANT      = "COMPLIANT"
	ACCESS_KEY_1   = "AccessKey1"
	ACCESS_KEY_2   = "AccessKey2"
)

// AWSAccessKeyRotationReport :
func (inst *TaskInstance) AWSAccessKeyRotationReport(inputs *UserInputs, outputs *Outputs) (defdErr error) {
	var errorVO *ErrorVO
	defer func() {
		if errorVO != nil {
			outputs.LogFile, defdErr = inst.uploadLogFile(errorVO)
		}
	}()

	// validating user object for aws connector creation
	errorVO = inst.validateApp()
	if errorVO != nil {
		return nil
	}

	awsConnector := awsconnector.AWSAppConnector{UserDefinedCredentials: &inst.UserObject.App.UserDefinedCredentials}
	err := awsConnector.ValidateStruct(inputs)
	if err != nil {
		errorVO = &ErrorVO{ErrorMessage: fmt.Sprintf("User inputs validation failed: %v", err.Error())}
		return nil
	}
	credentialReport := make([]AWSCredentialReportVO, 0)
	credReportFileBytes, err := storage.DownloadFile(inputs.AWSCredentialReport, inst.SystemInputs)
	if err != nil {
		errorVO = &ErrorVO{ErrorMessage: "Cannot download aws credential file from minio"}
		return nil
	}
	err = json.Unmarshal(credReportFileBytes, &credentialReport)
	if err != nil {
		errorVO = &ErrorVO{ErrorMessage: "Error while unmarshalling credential report"}
		return nil
	}
	if len(credentialReport) > ZERO {
		standardizedCredentialReport, err := inst.standardizeReportByKeyInfo(credentialReport, inputs.MaxAccessKeyAge, awsConnector)
		if err != nil {
			errorVO = &ErrorVO{ErrorMessage: err.Error()}
			return nil
		}
		outputs.AccessKeyRotationReport, err = inst.uploadOutputFile(standardizedCredentialReport)
		if err != nil {
			errorVO = &ErrorVO{ErrorMessage: err.Error()}
			return nil
		}
		outputs.MetaFile, err = inst.uploadMetaFile(standardizedCredentialReport, awsConnector)
		if err != nil {
			errorVO = &ErrorVO{ErrorMessage: err.Error()}
			return nil
		}
	} else {
		errorVO = &ErrorVO{ErrorMessage: "No records found in credential report"}
		return nil
	}

	return defdErr
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

/*
	    Standardizing the credential report based on access key details
		Standardize fields - System, Source, ResourceID, ResourceName, ResourceType, ResourceLocation, ResourceTags ...
		please refer notebook for detailed information
*/
func (inst *TaskInstance) standardizeReportByKeyInfo(credentialReport []AWSCredentialReportVO, maxAccessKeyAge int, awsConnector awsconnector.AWSAppConnector) ([]AccessKeyRotationVO, error) {

	accessKeysRotationData := make([]AccessKeyRotationVO, ZERO)

	for _, report := range credentialReport {

		validationResult, err := inst.validateKeyRotation(report, maxAccessKeyAge)
		if err != nil {
			return accessKeysRotationData, err
		}
		// Get resource URL for the user
		userName := report.User
		resourceUrl := NOT_APPLICABLE
		if userName != "root_account" {
			resourceUrl, err = awsConnector.GetResourceUrl(awsconnector.ResourceInfo{
				ResourceType: awsconnector.IAM_USER,
				Resource:     userName,
			})
			if err != nil {
				return accessKeysRotationData, fmt.Errorf("Error while fetching resource url for user - %v : %v", userName, err.Error())
			}
		}
		standardizedData := AccessKeyRotationVO{
			System:                 "aws",
			Source:                 "compliancecow",
			ResourceID:             report.ARN,
			ResourceName:           userName,
			ResourceType:           awsconnector.IAM_USER,
			ResourceLocation:       "global",
			ResourceURL:            resourceUrl,
			EvaluatedTime:          awsConnector.GetCurrentTime(),
			ComplianceStatus:       validationResult.ComplianceStatus,
			ComplianceStatusReason: validationResult.ComplianceStatusReason,
			ValidationStatusCode:   validationResult.ValidationStatusCode,
			ValidationStatusNotes:  validationResult.ValidationStatusNotes,
			AccessKey1Active:       report.AccessKey1Active,
			AccessKey1LastRotated:  report.AccessKey1LastRotated,
			AccessKey1Age:          validationResult.AccessKey1Age,
			Accesskey1LastUsedDate: report.Accesskey1LastUsedDate,
			AccessKey2Active:       report.AccessKey2Active,
			AccessKey2LastRotated:  report.AccessKey2LastRotated,
			AccessKey2Age:          validationResult.AccessKey2Age,
			Accesskey2LastUsedDate: report.Accesskey2LastUsedDate,
		}
		accessKeysRotationData = append(accessKeysRotationData, standardizedData)
	}

	return accessKeysRotationData, nil
}

func (inst *TaskInstance) validateKeyRotation(credentialReport AWSCredentialReportVO, maxAccessKeyAge int) (ValidationResult, error) {

	validationResult := ValidationResult{}

	// Default values
	complianceStatus := NON_COMPLIANT
	complianceStatusReason := "Access key was not applicable for the user."
	validationStatusCode := "ACC_KEY_NT_APL"
	validationStatusNotes := "Access key not applicable"
	validationResult.AccessKey1Age = NOT_APPLICABLE
	validationResult.AccessKey2Age = NOT_APPLICABLE

	// Check if both keys are applicable for rotation
	if credentialReport.AccessKey1LastRotated != NOT_APPLICABLE && credentialReport.AccessKey2LastRotated != NOT_APPLICABLE {

		key1Age, err := inst.calculateAccessKeyAge(credentialReport.AccessKey1LastRotated)
		if err != nil {
			return validationResult, err
		}
		key2Age, err := inst.calculateAccessKeyAge(credentialReport.AccessKey2LastRotated)
		if err != nil {
			return validationResult, err
		}

		if key1Age > maxAccessKeyAge && key2Age > maxAccessKeyAge {
			complianceStatusReason = "The record is not compliant as both access keys were not rotated properly"
			validationStatusCode = "BTH_ACC_KEY_NT_RTD"
			validationStatusNotes = "Both access keys have not been rotated"
		} else if key1Age <= maxAccessKeyAge && key2Age <= maxAccessKeyAge {
			complianceStatus = COMPLIANT
			complianceStatusReason = "Record is compliant as both access keys were rotated properly"
			validationStatusCode = "BTH_ACC_KEY_RTD"
			validationStatusNotes = "Both access keys have been rotated"
		} else if key1Age > maxAccessKeyAge && key2Age <= maxAccessKeyAge {
			complianceStatusReason = "Record is non compliant as accessKey1 was not rotated properly"
			validationStatusCode = "ACC_KY2_RTD_ACC_KY1_NT_RTD"
			validationStatusNotes = "AcessKey2 was rotated properly and accessKey1 was not rotated properly"
		} else if key1Age <= maxAccessKeyAge && key2Age > maxAccessKeyAge {
			complianceStatusReason = "Record is non compliant as accessKey2 was not rotated properly"
			validationStatusCode = "ACC_KY1_RTD_ACC_KY2_NT_RTD"
			validationStatusNotes = "AcessKey1 was rotated properly and accessKey2 was not rotated properly"
		}

		validationResult.AccessKey1Age = fmt.Sprintf("%d", key1Age)
		validationResult.AccessKey2Age = fmt.Sprintf("%d", key2Age)

		// check if accesskey1 is applicable for rotation
	} else if credentialReport.AccessKey1LastRotated != NOT_APPLICABLE && credentialReport.AccessKey2LastRotated == NOT_APPLICABLE {

		key1Age, err := inst.calculateAccessKeyAge(credentialReport.AccessKey1LastRotated)
		if err != nil {
			return validationResult, err
		}
		if key1Age <= maxAccessKeyAge {
			complianceStatus = COMPLIANT
			complianceStatusReason = "Record is compliant as accesskey1 was rotated properly"
			validationStatusCode = "ACC_KEY_RTD"
			validationStatusNotes = "Accesskey1 has been rotated"
		} else {
			complianceStatus = NON_COMPLIANT
			complianceStatusReason = "Record is not compliant as accesskey1 was not rotated properly"
			validationStatusCode = "ACC_KEY_NT_RTD"
			validationStatusNotes = "Accesskey1 has not been rotated"
		}
		validationResult.AccessKey1Age = fmt.Sprintf("%d", key1Age)

		// check if accesskey2 is applicable for rotation
	} else if credentialReport.AccessKey1LastRotated == NOT_APPLICABLE && credentialReport.AccessKey2LastRotated != NOT_APPLICABLE {

		key2Age, err := inst.calculateAccessKeyAge(credentialReport.AccessKey2LastRotated)
		if err != nil {
			return validationResult, err
		}
		if key2Age <= maxAccessKeyAge {
			complianceStatus = COMPLIANT
			complianceStatusReason = "Record is compliant as accesskey2 was rotated properly"
			validationStatusCode = "ACC_KEY_RTD"
			validationStatusNotes = "Accesskey2 has been rotated"
		} else {
			complianceStatus = NON_COMPLIANT
			complianceStatusReason = "Record is not compliant as accesskey2 was not rotated properly"
			validationStatusCode = "ACC_KEY_NT_RTD"
			validationStatusNotes = "Accesskey2 has not been rotated"
		}
		validationResult.AccessKey2Age = fmt.Sprintf("%d", key2Age)
	}

	validationResult.ComplianceStatus = complianceStatus
	validationResult.ComplianceStatusReason = complianceStatusReason
	validationResult.ValidationStatusCode = validationStatusCode
	validationResult.ValidationStatusNotes = validationStatusNotes

	return validationResult, nil

}

func (inst *TaskInstance) calculateAccessKeyAge(keyLastRotated string) (int, error) {

	if cowlibutils.IsEmpty(keyLastRotated) {
		return ZERO, fmt.Errorf("KeyLastRotated is required to calculate access key age")
	}
	//YYYY-MM-DDTHH:MM:SS±hh:mm
	layout := "2006-01-02T15:04:05Z"
	keyLastRotatedtime, err := time.Parse(layout, keyLastRotated)
	if err != nil {
		return ZERO, fmt.Errorf("Failed to parse keyLastRotatedtime: %w", err)
	}
	currentTime := time.Now()
	// Calculate the difference between keyLastRotatedtime and current time
	diff := currentTime.Sub(keyLastRotatedtime)
	// Extract the number of days from the difference
	days := int(diff.Hours() / 24)

	return days, nil
}

func (inst *TaskInstance) uploadOutputFile(outputData []AccessKeyRotationVO) (string, error) {
	reportFileNameWithUUID := fmt.Sprintf("%v-%v%v", "AccessKeyRotationReport", uuid.New().String(), ".json")
	outputFilePath, err := storage.UploadJSONFile(reportFileNameWithUUID, outputData, inst.SystemInputs)
	if err != nil {
		return "", fmt.Errorf("Cannot upload access key rotation data to minio: %w", err)
	}
	return outputFilePath, nil
}

func (inst *TaskInstance) uploadLogFile(errorList interface{}) (string, error) {
	auditFileNameWithUUID := fmt.Sprintf("%v-%v%v", "LogFile", uuid.New().String(), ".json")
	outputFilePath, err := storage.UploadJSONFile(auditFileNameWithUUID, errorList, inst.SystemInputs)
	if err != nil {
		return "", fmt.Errorf("Cannot upload log file to minio: %w", err)
	}
	return outputFilePath, nil
}

func (inst *TaskInstance) uploadMetaFile(outputData []AccessKeyRotationVO, awsConnector awsconnector.AWSAppConnector) (string, error) {
	if len(outputData) > 0 {
		fieldMetaData := awsConnector.CreateMetaFileData(outputData[0])
		metaFileNameWithUUID := fmt.Sprintf("%v-%v%v", "MetaFile", uuid.New().String(), ".json")
		outputFilePath, err := storage.UploadJSONFile(metaFileNameWithUUID, fieldMetaData, inst.SystemInputs)
		if err != nil {
			return "", fmt.Errorf("Cannot upload meta file to minio: %w", err)
		}
		return outputFilePath, nil
	}
	return "", nil
}

type ValidationResult struct {
	AccessKey2Age          string `json:"AccessKey2Age"`
	AccessKey1Age          string `json:"AccessKey1Age"`
	ValidationStatusCode   string `json:"ValidationStatusCode"`
	ValidationStatusNotes  string `json:"ValidationStatusNotes"`
	ComplianceStatus       string `json:"ComplianceStatus"`
	ComplianceStatusReason string `json:"ComplianceStatusReason"`
}

type AWSCredentialReportVO struct {
	User                      string `json:"User"`
	ARN                       string `json:"ARN"`
	UserCreationTime          string `json:"UserCreationTime"`
	PasswordEnabled           string `json:"PasswordEnabled"`
	PasswordLastUsed          string `json:"PasswordLastUsed"`
	PasswordLastChanged       string `json:"PasswordLastChanged"`
	PasswordNextRotation      string `json:"PasswordNextRotation"`
	MFAActive                 string `json:"MFAActive"`
	AccessKey1Active          string `json:"AccessKey1Active"`
	AccessKey1LastRotated     string `json:"AccessKey1LastRotated"`
	Accesskey1LastUsedDate    string `json:"Accesskey1LastUsedDate"`
	AccessKey1LastUsedRegion  string `json:"AccessKey1LastUsedRegion"`
	AccessKey1LastUsedService string `json:"AccessKey1LastUsedService"`
	AccessKey2Active          string `json:"AccessKey2Active"`
	AccessKey2LastRotated     string `json:"AccessKey2LastRotated"`
	Accesskey2LastUsedDate    string `json:"Accesskey2LastUsedDate"`
	AccessKey2LastUsedRegion  string `json:"AccessKey2LastUsedRegion"`
	AccessKey2LastUsedService string `json:"AccessKey2LastUsedService"`
	Cert1Active               string `json:"Cert1Active"`
	Cert1LastRotated          string `json:"Cert1LastRotated"`
	Cert2Active               string `json:"Cert2Active"`
	Cert2LastRotated          string `json:"Cert2LastRotated"`
}

type AccessKeyRotationVO struct {
	System                 string `json:"System"`
	Source                 string `json:"Source"`
	ResourceID             string `json:"ResourceID"`
	ResourceName           string `json:"ResourceName"`
	ResourceType           string `json:"ResourceType"`
	ResourceLocation       string `json:"ResourceLocation"`
	ResourceTags           []Tags `json:"Tags"`
	ResourceURL            string `json:"ResourceURL"`
	AccessKey1Active       string `json:"AccessKey1Active"`
	AccessKey1LastRotated  string `json:"AccessKey1LastRotated"`
	AccessKey1Age          string `json:"AccessKey1Age"`
	Accesskey1LastUsedDate string `json:"Accesskey1LastUsedDate"`
	AccessKey2Active       string `json:"AccessKey2Active"`
	AccessKey2LastRotated  string `json:"AccessKey2LastRotated"`
	AccessKey2Age          string `json:"AccessKey2Age"`
	Accesskey2LastUsedDate string `json:"Accesskey2LastUsedDates"`
	ValidationStatusCode   string `json:"ValidationStatusCode"`
	ValidationStatusNotes  string `json:"ValidationStatusNotes"`
	ComplianceStatus       string `json:"ComplianceStatus"`
	ComplianceStatusReason string `json:"ComplianceStatusReason"`
	EvaluatedTime          string `json:"EvaluatedTime"`
	UserAction             string `json:"UserAction"`
	ActionStatus           string `json:"ActionStatus"`
	ActionResponseURL      string `json:"ActionResponseURL"`
}

type ErrorVO struct {
	ErrorMessage string `json:"ErrorMessage"`
}

type Tags struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}
