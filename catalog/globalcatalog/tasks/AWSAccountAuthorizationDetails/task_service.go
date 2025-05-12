package main

import (
	awsconnector "applicationtypes/awsappconnector"
	storage "applicationtypes/minio"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/google/uuid"
)

// AWSAccountAuthorizationDetails :
func (inst *TaskInstance) AWSAccountAuthorizationDetails(inputs *UserInputs, outputs *Outputs) (deferredErr error) {
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

	accAuthDetails, err := awsConnector.GetAccountAuthorizationDetails(&iam.GetAccountAuthorizationDetailsInput{})
	if err != nil {
		errorDetails = ErrorVO{Error: err.Error()}
		return nil
	}
	if accAuthDetails != nil {
		outputs.AccountAuthorizationDetails, err = inst.uploadOutputFile(accAuthDetails)
		if err != nil {
			errorDetails = ErrorVO{Error: err.Error()}
			return nil
		}
	} else {
		errorDetails = ErrorVO{Error: "No AWS account authorization details found"}
		return nil
	}

	return deferredErr
}

func (inst *TaskInstance) uploadOutputFile(outputData *iam.GetAccountAuthorizationDetailsOutput) (string, error) {
	fileContent := make([]*iam.GetAccountAuthorizationDetailsOutput, 0)
	fileContent = append(fileContent, outputData)
	outputFileNameWithUUID := fmt.Sprintf("%v-%v%v", "AccountAuthorizationDetails", uuid.New().String(), ".json")
	outputFilePath, err := storage.UploadJSONFile(outputFileNameWithUUID, fileContent, inst.SystemInputs)
	if err != nil {
		return "", fmt.Errorf("Failed to upload account authorization details to Minio: %w", err)
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

type ErrorVO struct {
	Error string `json:"Error"`
}
