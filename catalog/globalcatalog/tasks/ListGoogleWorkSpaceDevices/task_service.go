package main

import (
	googleworkspaceappconnector "applicationtypes/googleworkspaceappconnector"
	"fmt"

	storage "applicationtypes/minio"

	"github.com/google/uuid"
)

// ListGoogleWorkSpaceDevices :
func (inst *TaskInstance) ListGoogleWorkSpaceDevices(inputs *UserInputs, outputs *Outputs) (defErr error) {

	var errorVO []*ErrorVO
	defer func() {
		if errorVO != nil {
			outputs.LogFile, defErr = storage.UploadJSONFile(fmt.Sprintf("%v-%v%v", "LogFile", uuid.New().String(), ".json"), errorVO, inst.SystemInputs)
		}
	}()
	outputs.CompliancePCT_ = 0
	outputs.ComplianceStatus_ = "NOT_DETERMINED"

	// validating user object for googleworkspaceappConnector creation
	errorVO = inst.validateApp()
	if errorVO != nil {
		return nil
	}

	googleworkspaceappConnector := googleworkspaceappconnector.GoogleWorkSpaceAppConnector{
		UserDefinedCredentials: &inst.UserObject.App.UserDefinedCredentials,
	}

	// Mobile devices
	mobileDevices, err := googleworkspaceappConnector.ListMobileDevices()
	if err != nil {
		errorVO = append(errorVO, &ErrorVO{ErrorMessage: err.Error()})
		return nil
	}

	outputs.MobileDevicesReport, defErr = storage.UploadJSONFile(fmt.Sprintf("%v-%v%v", "MobileDevices", uuid.New().String(), ".json"), mobileDevices, inst.SystemInputs)
	if defErr != nil {
		errorVO = append(errorVO, &ErrorVO{ErrorMessage: defErr.Error()})
		return nil
	}

	return defErr
}

func (inst *TaskInstance) validateApp() []*ErrorVO {
	var errorVO []*ErrorVO
	if inst.UserObject == nil {
		errorVO = append(errorVO, &ErrorVO{ErrorMessage: "User object is missing."})
		return errorVO
	}
	if inst.UserObject.App == nil {
		errorVO = append(errorVO, &ErrorVO{ErrorMessage: "Application detail is missing."})
		return errorVO
	}
	if inst.UserObject.App.UserDefinedCredentials == (googleworkspaceappconnector.UserDefinedCredentials{}) {
		errorVO = append(errorVO, &ErrorVO{ErrorMessage: "User defined credentials is missing."})
		return errorVO
	}
	return nil
}

type ErrorVO struct {
	ErrorMessage string `json:"Error"`
}
