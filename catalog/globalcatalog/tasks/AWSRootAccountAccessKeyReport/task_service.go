package main

import (
	awsconnector "appconnections/awsappconnector"
	storage "appconnections/minio"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

const (
	ZERO           = 0
	TRUE           = "true"
	FALSE          = "false"
	NOT_APPLICABLE = "N/A"
)

// AWSRootAccountAccessKeyReport :
func (inst *TaskInstance) AWSRootAccountAccessKeyReport(inputs *UserInputs, outputs *Outputs) (deferr error) {
	var errorVO *ErrorVO
	defer func() {
		if errorVO != nil {
			outputs.LogFile, deferr = inst.uploadLogFile(errorVO)
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
	standardizedCredReport, err := inst.standardizeCredReportByRootAccessKeyData(credentialReport, awsConnector)
	if err != nil {
		errorVO = &ErrorVO{ErrorMessage: fmt.Sprintf("Error while standardizing credential report: %v", err.Error())}
		return nil
	}
	if len(standardizedCredReport) > 0 {
		outputs.NoAccessKeyWithRootAccount, err = inst.uploadOutputFile(standardizedCredReport)
		if err != nil {
			errorVO = &ErrorVO{ErrorMessage: fmt.Sprintf("Error while standardizing credential report: %v", err.Error())}
			return nil
		}
	} else {
		errorVO = &ErrorVO{ErrorMessage: "The root account record is not found in the input AWS credential report."}
		return nil
	}
	return deferr

}

func (inst *TaskInstance) readCredentialReport(data []interface{}) ([]AWSCredentialReportVO, error) {
	var awsCredentialReportVO []AWSCredentialReportVO
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal aws credential details: %w", err)
	}
	if err := json.Unmarshal(dataBytes, &awsCredentialReportVO); err != nil {
		return nil, fmt.Errorf("Failed to unmarshal aws credential details: %w", err)
	}
	return awsCredentialReportVO, nil
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

func (inst *TaskInstance) standardizeCredReportByRootAccessKeyData(credReport []AWSCredentialReportVO, awsConnector awsconnector.AWSAppConnector) ([]RootAccountAccessKeyVO, error) {
	var accessKey1Status, accessKey2Status, complianceStatusReason, complianceStatus, validationStatusCode, validationStatusNotes string
	rootAccAccessKeyData := make([]RootAccountAccessKeyVO, 0)
	for _, report := range credReport {
		userName := report.User
		if userName == "root_account" {
			if report.AccessKey1Active == TRUE {
				accessKey1Status = "AccessKey1 is active"
			} else if report.AccessKey1Active == FALSE && report.AccessKey1LastRotated == NOT_APPLICABLE {
				accessKey1Status = "AccessKey1 does not exist"
			} else if report.AccessKey1Active == FALSE && report.AccessKey1LastRotated != NOT_APPLICABLE {
				accessKey1Status = "AccessKey1 is inactive"
			}
			if report.AccessKey2Active == TRUE {
				accessKey2Status = "AccessKey2 is active"
			} else if report.AccessKey2Active == FALSE && report.AccessKey2LastRotated == NOT_APPLICABLE {
				accessKey2Status = "AccessKey2 does not exist"
			} else if report.AccessKey2Active == FALSE && report.AccessKey2LastRotated != NOT_APPLICABLE {
				accessKey2Status = "AccessKey2 is inactive"
			}
			if accessKey1Status == "AccessKey1 does not exist" && accessKey2Status == "AccessKey2 does not exist" {
				complianceStatus = "COMPLIANT"
				complianceStatusReason = "Record is compliant as the root account does not have any access key"
				validationStatusCode = "ACS_KY_NT_EXT"
				validationStatusNotes = "access key not exist for the root account"
			} else {
				complianceStatus = "NON_COMPLIANT"
				complianceStatusReason = "Record is not compliant as the root account has access key"
				validationStatusCode = "ACS_KY_EXT"
				validationStatusNotes = "Access key exist for the root account"
			}
			data := RootAccountAccessKeyVO{
				System:                 "aws",
				Source:                 "compliancecow",
				ResourceID:             userName,
				ResourceName:           "root_account",
				ResourceType:           "AwsIamUser",
				ResourceLocation:       "global",
				ResourceURL:            "N/A",
				AccessKey1Status:       accessKey1Status,
				AccessKey2Status:       accessKey2Status,
				ValidationStatusCode:   validationStatusCode,
				ValidationStatusNotes:  validationStatusNotes,
				ComplianceStatus:       complianceStatus,
				ComplianceStatusReason: complianceStatusReason,
				EvaluatedTime:          awsConnector.GetCurrentTime(),
			}
			rootAccAccessKeyData = append(rootAccAccessKeyData, data)
			break
		}
	}
	return rootAccAccessKeyData, nil
}

func (inst *TaskInstance) uploadOutputFile(outputData []RootAccountAccessKeyVO) (string, error) {
	reportFileNameWithUUID := fmt.Sprintf("%v-%v%v", "NoAccessKeyWithRootAccount", uuid.New().String(), ".json")
	outputFilePath, err := storage.UploadJSONFile(reportFileNameWithUUID, outputData, inst.SystemInputs)
	if err != nil {
		return "", fmt.Errorf("Cannot upload root account access key data to minio: %w", err)
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

func (inst *TaskInstance) uploadMetaFile(outputData []RootAccountAccessKeyVO, awsConnector awsconnector.AWSAppConnector) (string, error) {
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

type RootAccountAccessKeyVO struct {
	System                 string `json:"System"`
	Source                 string `json:"Source"`
	ResourceID             string `json:"ResourceID"`
	ResourceName           string `json:"ResourceName"`
	ResourceType           string `json:"ResourceType"`
	ResourceLocation       string `json:"ResourceLocation"`
	ResourceTags           []Tags `json:"Tags"`
	ResourceURL            string `json:"ResourceURL"`
	AccessKey1Status       string `json:"AccessKey1Status"`
	AccessKey2Status       string `json:"AccessKey2Status"`
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
