package main

import (
	googleworkspaceappconnector "applicationtypes/googleworkspaceappconnector"
	storage "applicationtypes/minio"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// GoogleWorkSpaceManagedDevicesReport :
func (inst *TaskInstance) GoogleWorkSpaceManagedDevicesReport(inputs *UserInputs, outputs *Outputs) (defErr error) {

	var errorVO []*ErrorVO
	defer func() {
		if errorVO != nil {
			outputs.CompliancePCT_ = 0
			outputs.ComplianceStatus_ = "NOT_DETERMINED"
			outputs.LogFile, defErr = storage.UploadJSONFile(fmt.Sprintf("%v-%v%v", "LogFile", uuid.New().String(), ".json"), errorVO, inst.SystemInputs)
		}
	}()

	// validating user object for googleworkspaceadminConnector creation
	errorVO = inst.validateApp()
	if errorVO != nil {
		return nil
	}

	googleWorkSpaceMobileDeviceList := make([]googleworkspaceappconnector.MobileDevice, 0)
	googleWorkSpaceMobileDeviceBytes, err := storage.DownloadFile(inputs.MobileDevicesReport, inst.SystemInputs)
	if err != nil {
		errorVO = append(errorVO, &ErrorVO{ErrorMessage: "Cannot download GoogleWorkSpaceMobileDevice file from minio"})
		return nil
	}
	err = json.Unmarshal(googleWorkSpaceMobileDeviceBytes, &googleWorkSpaceMobileDeviceList)
	if err != nil {
		errorVO = append(errorVO, &ErrorVO{ErrorMessage: "Error while unmarshalling GoogleWorkSpaceMobileDeviceList"})
		return nil
	}

	if len(googleWorkSpaceMobileDeviceList) > 0 {
		standardizedData, err := inst.standardizeData(googleWorkSpaceMobileDeviceList)
		if err != nil {
			errorVO = append(errorVO, &ErrorVO{ErrorMessage: "Error while standardizing googleWorkSpaceMobileDeviceList"})
			return nil
		}
		outputs.GoogleWorkSpaceManagedDeviceReport, defErr = storage.UploadJSONFile(fmt.Sprintf("%v-%v%v", "GoogleWorkSpaceManagedDeviceReport", uuid.New().String(), ".json"), standardizedData, inst.SystemInputs)
	} else {
		errorVO = append(errorVO, &ErrorVO{ErrorMessage: "GoogleWorkSpaceMobileDeviceList is empty"})
		return nil
	}

	return nil
}

func (inst *TaskInstance) standardizeData(mobileDeviceList []googleworkspaceappconnector.MobileDevice) ([]MobileDevice, error) {

	mobileDevices := make([]MobileDevice, 0)

	for _, device := range mobileDeviceList {
		mobileDevice := MobileDevice{
			System:       device.System,
			Source:       device.Source,
			ResourceID:   device.ResourceId,
			ResourceType: device.ResourceType,
			Status:       device.Status,
			UserName:     device.UserName,
			UserEmail:    device.UserEmail,
		}
		mobileDevice.ComplianceStatus = "NON_COMPLIANT"
		mobileDevice.ComplianceStatusReason = "The record is not complaint as the mobile device is not managed in user's google workspace account"
		mobileDevice.ValidationStatusCode = "MB_DV_NT_APD"
		mobileDevice.ValidationStatusNotes = "Mobile devices is not approved"
		if device.Status == "APPROVED" {
			mobileDevice.ComplianceStatus = "COMPLIANT"
			mobileDevice.ComplianceStatusReason = "The record is complaint as the mobile device is managed in user's google workspace account"
			mobileDevice.ValidationStatusCode = "MB_DV_APD"
			mobileDevice.ValidationStatusNotes = "Mobile device is approved"
		}
		mobileDevices = append(mobileDevices, mobileDevice)
	}

	return mobileDevices, nil

}

type ErrorVO struct {
	ErrorMessage string `json:"Error"`
}

func (inst *TaskInstance) validateApp() []*ErrorVO {
	var errorVO []*ErrorVO
	if inst.UserObject == nil {
		errorVO = append(errorVO, &ErrorVO{ErrorMessage: "user object is missing."})
		return errorVO
	}
	if inst.UserObject.App == nil {
		errorVO = append(errorVO, &ErrorVO{ErrorMessage: "application detail is missing."})
		return errorVO
	}
	if inst.UserObject.App.UserDefinedCredentials == (googleworkspaceappconnector.UserDefinedCredentials{}) {
		errorVO = append(errorVO, &ErrorVO{ErrorMessage: "user defined credentials is missing."})
		return errorVO
	}
	return nil
}

type MobileDevice struct {
	System                 string   `json:"System"`
	Source                 string   `json:"Source"`
	ResourceID             string   `json:"ResourceID"`
	ResourceType           string   `json:"ResourceType"`
	ResourceURL            string   `json:"ResourceUrl"`
	Status                 string   `json:"Status"`
	UserEmail              []string `json:"UserEmail"`
	UserName               []string `json:"UserName"`
	ValidationStatusCode   string   `json:"ValidationStatusCode"`
	ValidationStatusNotes  string   `json:"ValidationStatusNotes"`
	ComplianceStatus       string   `json:"ComplianceStatus"`
	ComplianceStatusReason string   `json:"ComplianceStatusReason"`
	EvaluatedTime          string   `json:"EvaluatedTime"`
	UserAction             string   `json:"UserAction"`
	ActionStatus           string   `json:"ActionStatus"`
	ActionResponseURL      string   `json:"ActionResponseURL"`
}
