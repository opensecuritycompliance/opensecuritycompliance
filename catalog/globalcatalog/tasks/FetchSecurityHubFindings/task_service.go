package main

import (
	awsconnector "appconnections/awsappconnector"
	storage "appconnections/minio"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/google/uuid"
)

const (
	auditFileName  = "LogFile"
	outputFileName = "AWSSecurityHubFindings"
)

// FetchSecurityHubFindings :
func (inst *TaskInstance) FetchSecurityHubFindings(inputs *UserInputs, outputs *Outputs) (deferredErr error) {

	defer func() {
		if outputs.ErrorDetails != nil {
			errorList := map[string]interface{}{
				"Error": outputs.ErrorDetails.Error(),
			}
			outputs.LogFile, deferredErr = inst.uploadAuditFile(errorList)
		}
	}()
	err := inst.validateApp()
	if err != nil {
		outputs.ErrorDetails = err
		return nil
	}
	awsConnector := awsconnector.AWSAppConnector{UserDefinedCredentials: &inst.UserObject.App.UserDefinedCredentials,
		Region: inputs.Region}
	err = awsConnector.ValidateStruct(inputs)
	if err != nil {
		outputs.ErrorDetails = err
		return nil
	}

	productName := strings.Split(inputs.AWSProductName, ",")
	recordState := strings.Split(inputs.FindingsRecordState, ",")
	input := &securityhub.GetFindingsInput{
		Filters: &securityhub.AwsSecurityFindingFilters{
			ProductName: awsConnector.GetSecurityHubFindingsInput(productName),
			RecordState: awsConnector.GetSecurityHubFindingsInput(recordState),
		},
	}

	findings, errorList := awsConnector.GetSecurityHubFindings(input)
	if errorList != nil {
		outputs.LogFile, err = inst.uploadAuditFile(errorList)
		if err != nil {
			outputs.ErrorDetails = err
			return nil
		}
	}
	if findings != nil {
		outputs.SecurityHubFindingsFile, err = inst.uploadOutputFile(findings)
		if err != nil {
			outputs.ErrorDetails = err
			return nil
		}
	}

	outputs.CompliancePCT_ = 0
	outputs.ComplianceStatus_ = "NOT_DETERMINED"
	return deferredErr
}

func (inst *TaskInstance) uploadOutputFile(outputFindings []*securityhub.AwsSecurityFinding) (string, error) {
	reportFileNameWithUUID := fmt.Sprintf("%v-%v%v", outputFileName, uuid.New().String(), ".json")
	outputFilePath, err := storage.UploadJSONFile(reportFileNameWithUUID, outputFindings, inst.SystemInputs)
	if err != nil {
		return "", fmt.Errorf("Cannot upload securityhub findings data to minio: %w", err)
	}
	return outputFilePath, nil
}

func (inst *TaskInstance) uploadAuditFile(errorList interface{}) (string, error) {
	var err error
	auditFileNameWithUUID := fmt.Sprintf("%v-%v%v", auditFileName, uuid.New().String(), ".json")
	outputFilePath, err := storage.UploadJSONFile(auditFileNameWithUUID, errorList, inst.SystemInputs)
	if err != nil {
		return "", fmt.Errorf("Cannot upload audit file to minio: %w", err)
	}
	return outputFilePath, nil
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
