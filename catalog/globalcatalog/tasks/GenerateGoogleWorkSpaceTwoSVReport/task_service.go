package main

import (
	"appconnections/googleworkspaceappconnector"
	"encoding/json"
	"fmt"

	storage "appconnections/minio"

	"github.com/google/uuid"
)

// GenerateGoogleWorkSpaceTwoSVReport :
func (inst *TaskInstance) GenerateGoogleWorkSpaceTwoSVReport(inputs *UserInputs, outputs *Outputs) (defErr error) {

	var errorVO *ErrorVO
	defer func() {
		if errorVO != nil {
			outputs.LogFile, defErr = storage.UploadJSONFile(fmt.Sprintf("%v-%v%v", "LogFile", uuid.New().String(), ".json"), errorVO, inst.SystemInputs)
		}
	}()

	// validating user object for googleworkspaceadminConnector creation
	errorVO = inst.validateApp()
	if errorVO != nil {
		return nil
	}

	googleWorkSpaceUserList := make([]User, 0)
	googleWorkSpaceUserListBytes, err := storage.DownloadFile(inputs.GoogleWorkSpaceUsersListFile, inst.SystemInputs)
	if err != nil {
		errorVO = &ErrorVO{ErrorMessage: "cannot download GoogleWorkSpaceUsersList file from minio"}
		return nil
	}
	err = json.Unmarshal(googleWorkSpaceUserListBytes, &googleWorkSpaceUserList)
	if err != nil {
		errorVO = &ErrorVO{ErrorMessage: "error while unmarshalling GoogleWorkSpaceUsersList"}
		return nil
	}

	if len(googleWorkSpaceUserList) > 0 {
		standardizedData, err := inst.standardizeUserList(googleWorkSpaceUserList)
		if err != nil {
			errorVO = &ErrorVO{ErrorMessage: "error while standardizing GoogleWorkSpaceUsersList"}
			return nil
		}
		outputs.EnforcePhishingResistantMFA, defErr = storage.UploadJSONFile(fmt.Sprintf("%v-%v%v", "EnforcePhishingResistantMFA", uuid.New().String(), ".json"), standardizedData, inst.SystemInputs)
	} else {
		errorVO = &ErrorVO{ErrorMessage: "GoogleWorkSpaceUsersListFile is empty"}
		return nil
	}

	return defErr
}

func (inst *TaskInstance) standardizeUserList(users []User) ([]MFAReport, error) {

	mfaReport := make([]MFAReport, 0)

	for _, user := range users {
		data := MFAReport{
			System:          user.System,
			Source:          user.Source,
			ResourceType:    user.ResourceType,
			ResourceID:      user.ResourceID,
			ResourceName:    user.ResourceName,
			Email:           user.Email,
			LastLogin:       user.LastLogin,
			CreationDate:    user.CreationDate,
			IsAdmin:         user.IsAdmin,
			IsMFAEnrolled:   user.IsEnrolledIn2Sv,
			IsMFAEnforced:   user.IsEnforcedIn2Sv,
			AccountStatus:   user.AccountStatus,
			DeletionDate:    user.DeletionTime,
			SuspendedReason: user.SuspendedReason,
		}

		// default values
		data.ComplianceStatus = "NON_COMPLIANT"
		data.ComplianceStatusReason = "The record does not meet compliance standards due to the absence of two step verfication being enabled for the user"
		data.ValidationStatusCode = "AD_F_2F_ER_F_2F_EF_F"
		data.ValidationStatusNotes = "Admin false, 2FA Enrolled false, 2FA Enforced false"
		if user.IsAdmin {
			data.ValidationStatusCode = "AD_T_2F_ER_F_2F_EF_F"
			data.ValidationStatusNotes = "Admin true, 2FA Enrolled false, 2FA Enforced false"
		}

		// handle different use cases
		if !user.IsEnrolledIn2Sv && user.IsEnforcedIn2Sv {
			data.ComplianceStatusReason = "The record does not meet compliance standards due to the absence of two step verfication being enforced for the user"
			data.ValidationStatusCode = "AD_F_2F_ER_F_2F_EF_T"
			data.ValidationStatusNotes = "Admin false, 2FA Enrolled false, 2FA Enforced true"
			if user.IsAdmin {
				data.ValidationStatusCode = "AD_T_2F_ER_F_2F_EF_T"
				data.ValidationStatusNotes = "Admin true, 2FA Enrolled false, 2FA Enforced true"
			}
		}

		if user.IsEnrolledIn2Sv && !user.IsEnforcedIn2Sv {
			data.ComplianceStatusReason = "The record does not meet compliance standards due to the absence of two step verfication being enrolled for the user"
			data.ValidationStatusCode = "AD_F_2F_ER_T_2F_EF_F"
			data.ValidationStatusNotes = "Admin false, 2FA Enrolled true, 2FA Enforced false"
			if user.IsAdmin {
				data.ValidationStatusCode = "AD_T_2F_ER_T_2F_EF_F"
				data.ValidationStatusNotes = "Admin true, 2FA Enrolled true, 2FA Enforced false"
			}
		}

		if user.IsEnrolledIn2Sv && user.IsEnforcedIn2Sv {
			data.ComplianceStatus = "COMPLIANT"
			data.ComplianceStatusReason = "The record meets compliance standards due to the presence of two step verfication being enabled for the user"
			data.ValidationStatusCode = "AD_F_2F_ER_T_2F_EF_T"
			data.ValidationStatusNotes = "Admin false, 2FA Enrolled true, 2FA Enforced true"
			if user.IsAdmin {
				data.ValidationStatusCode = "AD_T_2F_ER_T_2F_EF_T"
				data.ValidationStatusNotes = "Admin true, 2FA Enrolled true, 2FA Enforced true"
			}
		}

		mfaReport = append(mfaReport, data)
	}

	return mfaReport, nil

}

func (inst *TaskInstance) validateApp() *ErrorVO {
	if inst.UserObject == nil {
		return &ErrorVO{ErrorMessage: "user object is missing."}
	}
	if inst.UserObject.App == nil {
		return &ErrorVO{ErrorMessage: "application detail is missing."}
	}
	if inst.UserObject.App.UserDefinedCredentials == (googleworkspaceappconnector.UserDefinedCredentials{}) {
		return &ErrorVO{ErrorMessage: "user defined credentials is missing."}
	}
	return nil
}

type ErrorVO struct {
	ErrorMessage string `json:"ErrorMessage"`
}

type User struct {
	System                      string                                `json:"System"`
	Source                      string                                `json:"Source"`
	ResourceType                string                                `json:"ResourceType"`
	ResourceID                  string                                `json:"ResourceID"`
	ResourceName                string                                `json:"ResourceName"`
	Email                       string                                `json:"Email"`
	LastLogin                   string                                `json:"LastLogin"`
	CreationDate                string                                `json:"CreationDate"`
	IsAdmin                     bool                                  `json:"IsAdmin"`
	IsEnforcedIn2Sv             bool                                  `json:"IsEnforcedIn2Sv"`
	IsEnrolledIn2Sv             bool                                  `json:"IsEnrolledIn2Sv"`
	AccountStatus               string                                `json:"AccountStatus"`
	DeletionTime                string                                `json:"DeletionTime"`
	SuspendedReason             string                                `json:"SuspendedReason"`
	Manager                     string                                `json:"Manager"`
	DeviceAssociations          string                                `json:"DeviceAssociations"`
	Permissions                 string                                `json:"Permissions"`
	ExternalAccess              string                                `json:"ExternalAccess"`
	TerminationConfirmedBy      string                                `json:"TerminationConfirmedBy"`
	TerminationConfirmationDate string                                `json:"TerminationConfirmationDate"`
	AdditionalInformation       string                                `json:"AdditionalInformation"`
	Groups                      []googleworkspaceappconnector.GroupVO `json:"Groups"`
	Roles                       []string                              `json:"Roles"`
	Privileges                  []string                              `json:"Privileges"`
}

type MFAReport struct {
	System                 string `json:"System"`
	Source                 string `json:"Source"`
	ResourceID             string `json:"ResourceID"`
	ResourceName           string `json:"ResourceName"`
	ResourceType           string `json:"ResourceType"`
	ResourceURL            string `json:"ResourceUrl"`
	Email                  string `json:"Email"`
	LastLogin              string `json:"LastLogin"`
	CreationDate           string `json:"CreationDate"`
	IsAdmin                bool   `json:"IsAdmin"`
	IsMFAEnrolled          bool   `json:"IsMFAEnrolled"`
	IsMFAEnforced          bool   `json:"IsMFAEnforced"`
	AccountStatus          string `json:"AccountStatus"`
	SuspendedReason        string `json:"SuspendedReason"`
	DeletionDate           string `json:"DeletionDate"`
	ValidationStatusCode   string `json:"ValidationStatusCode"`
	ValidationStatusNotes  string `json:"ValidationStatusNotes"`
	ComplianceStatus       string `json:"ComplianceStatus"`
	ComplianceStatusReason string `json:"ComplianceStatusReason"`
	EvaluatedTime          string `json:"EvaluatedTime"`
	UserAction             string `json:"UserAction"`
	ActionStatus           string `json:"ActionStatus"`
	ActionResponseURL      string `json:"ActionResponseURL"`
}
