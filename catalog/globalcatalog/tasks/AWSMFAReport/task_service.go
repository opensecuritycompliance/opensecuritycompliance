package main

import (
	awsconnector "applicationtypes/awsappconnector"
	storage "applicationtypes/minio"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

const (
	ZERO = 0
	TRUE = "true"
)

// AWSMFAReport :
func (inst *TaskInstance) AWSMFAReport(inputs *UserInputs, outputs *Outputs) (deferr error) {
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
	if len(credentialReport) > ZERO {
		standardizeMFAData, err := inst.standardizeMFAData(credentialReport, awsConnector)
		if err != nil {
			errorVO = &ErrorVO{ErrorMessage: err.Error()}
			return nil
		}
		outputs.AWSMFAReport, err = inst.uploadOutputFile(standardizeMFAData)
		if err != nil {
			errorVO = &ErrorVO{ErrorMessage: fmt.Sprintf("Error while uploading AWS MFA deials: %v", err.Error())}
			return nil
		}
		outputs.MetaFile, err = inst.uploadMetaFile(standardizeMFAData, awsConnector)
		if err != nil {
			errorVO = &ErrorVO{ErrorMessage: fmt.Sprintf("Error while uploading meta data report: %v", err.Error())}
			return nil
		}
	} else {
		errorVO = &ErrorVO{ErrorMessage: "No users for this AWS account."}
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

/*
	    Standardizing the credential report based on MFA active
		Standardize fields - System, Source, ResourceID, ResourceName, ResourceType, ResourceLocation, ResourceTags, MFAEnforced ,ValidationStatusCode, ComplianceStatus, ComplianceStatusReason, EvaluatedTime, UserAction, ActionStatus, ActionResponseURL
		please refer notebook for detailed information
*/
func (inst *TaskInstance) standardizeMFAData(credentialReport []AWSCredentialReportVO, awsConnector awsconnector.AWSAppConnector) ([]AWSMFAVO, error) {
	mfaData := make([]AWSMFAVO, 0)
	for _, report := range credentialReport {
		var complianceStatusReason, complianceStatus, validationStatusCode, validationStatusNotes string
		if report.PasswordEnabled == TRUE {
			if report.MFAActive == TRUE {
				complianceStatus = "COMPLIANT"
				complianceStatusReason = "Record is compliant as MFA is enforced"
				validationStatusCode = "MFA_PR"
				validationStatusNotes = "MFA present"
			} else {
				complianceStatus = "NON_COMPLIANT"
				complianceStatusReason = "Record is not compliant as MFA is not enforced"
				validationStatusCode = "MFA_NP"
				validationStatusNotes = "MFA not present"
			}
			resourceUrl, err := awsConnector.GetResourceUrl(awsconnector.ResourceInfo{
				ResourceType: awsconnector.IAM_USER,
				Resource:     report.User,
			})
			if err != nil {
				return mfaData, fmt.Errorf("Error while fetching resource url for user - %v :: %v", report.User, err.Error())
			}
			data := AWSMFAVO{
				System:                 "aws",
				Source:                 "compliancecow",
				ResourceID:             report.ARN,
				ResourceName:           report.User,
				ResourceType:           awsconnector.IAM_USER,
				ResourceLocation:       "global",
				ResourceURL:            resourceUrl,
				MFAEnforced:            report.MFAActive,
				ValidationStatusCode:   validationStatusCode,
				ValidationStatusNotes:  validationStatusNotes,
				ComplianceStatus:       complianceStatus,
				ComplianceStatusReason: complianceStatusReason,
				EvaluatedTime:          awsConnector.GetCurrentTime(),
			}
			mfaData = append(mfaData, data)
		}

	}
	return mfaData, nil
}

func (inst *TaskInstance) uploadOutputFile(outputData []AWSMFAVO) (string, error) {
	reportFileNameWithUUID := fmt.Sprintf("%v-%v%v", "MFAEnforced", uuid.New().String(), ".json")
	outputFilePath, err := storage.UploadJSONFile(reportFileNameWithUUID, outputData, inst.SystemInputs)
	if err != nil {
		return "", fmt.Errorf("Cannot upload aws mfa report to minio: %w", err)
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

func (inst *TaskInstance) uploadMetaFile(outputData []AWSMFAVO, awsConnector awsconnector.AWSAppConnector) (string, error) {
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

type AWSMFAVO struct {
	System                 string `json:"System"`
	Source                 string `json:"Source"`
	ResourceID             string `json:"ResourceID"`
	ResourceName           string `json:"ResourceName"`
	ResourceType           string `json:"ResourceType"`
	ResourceLocation       string `json:"ResourceLocation"`
	ResourceTags           []Tags `json:"Tags"`
	ResourceURL            string `json:"ResourceURL"`
	MFAEnforced            string `json:"MFAEnforced"`
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
