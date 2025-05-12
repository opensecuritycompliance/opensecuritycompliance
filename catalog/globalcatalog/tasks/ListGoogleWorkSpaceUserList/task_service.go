package main

import (
	"applicationtypes/googleworkspaceappconnector"
	storage "applicationtypes/minio"
	cowlibutils "cowlibrary/utils"
	"fmt"

	"github.com/google/uuid"
	admin "google.golang.org/api/admin/directory/v1"
)

// ListGoogleWorkSpaceUserList :
func (inst *TaskInstance) ListGoogleWorkSpaceUserList(inputs *UserInputs, outputs *Outputs) (defErr error) {

	var errorVO []*ErrorVO
	defer func() {
		if errorVO != nil {
			outputs.LogFile, defErr = storage.UploadJSONFile(fmt.Sprintf("%v-%v%v", "LogFile", uuid.New().String(), ".json"), errorVO, inst.SystemInputs)
		}
	}()

	// validating user object for googleworkspaceappConnector creation
	errorVO = inst.validateApp()
	if errorVO != nil {
		return nil
	}

	googleworkspaceappConnector := googleworkspaceappconnector.GoogleWorkSpaceAppConnector{
		UserDefinedCredentials: &inst.UserObject.App.UserDefinedCredentials,
	}

	var userList []User

	users, err := googleworkspaceappConnector.ListUsers()
	if err != nil {
		errorVO = append(errorVO, &ErrorVO{ErrorMessage: err.Error()})
		return nil
	}
	if len(users) > 0 {
		userList, err = inst.formatUser(users, googleworkspaceappConnector, userList)
		if err != nil {
			errorVO = append(errorVO, &ErrorVO{ErrorMessage: err.Error()})
			return nil
		}
	} else {
		errorVO = append(errorVO, &ErrorVO{ErrorMessage: "active users list is empty for given credentials"})
	}

	// fetching the deleted users
	deletedUsers, err := googleworkspaceappConnector.ListDeletedUsers()
	if err != nil {
		errorVO = append(errorVO, &ErrorVO{ErrorMessage: err.Error()})
		return nil
	}
	if len(deletedUsers) > 0 {
		userList, err = inst.formatUser(deletedUsers, googleworkspaceappConnector, userList)
		if err != nil {
			errorVO = append(errorVO, &ErrorVO{ErrorMessage: err.Error()})
			return nil
		}
	}

	if len(userList) > 0 {
		outputs.GooogleWorkSpaceUserList, err = storage.UploadJSONFile(fmt.Sprintf("%v-%v%v", "GooogleWorkSpaceUserList", uuid.New().String(), ".json"), userList, inst.SystemInputs)
		if err != nil {
			return err
		}
	}

	return defErr
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

func (inst *TaskInstance) formatUser(users []*admin.User, googleWorkSpaceConnector googleworkspaceappconnector.GoogleWorkSpaceAppConnector, formattedUsers []User) ([]User, error) {

	for _, user := range users {
		formattedUser := User{
			System:          "google_workspace",
			Source:          "compliancecow",
			ResourceType:    "user",
			ResourceName:    user.Name.FullName,
			ResourceID:      user.Id,
			Email:           user.PrimaryEmail,
			LastLogin:       user.LastLoginTime,
			CreationDate:    user.CreationTime,
			IsAdmin:         user.IsAdmin,
			IsEnrolledIn2Sv: user.IsEnrolledIn2Sv,
			IsEnforcedIn2Sv: user.IsEnforcedIn2Sv,
			Roles:           []string{},
			Privileges:      []string{},
			Groups:          []googleworkspaceappconnector.GroupVO{},
		}

		// user status
		if user.Suspended {
			formattedUser.AccountStatus = "Suspended"
			formattedUser.SuspendedReason = user.SuspensionReason
		} else if cowlibutils.IsNotEmpty(user.DeletionTime) {
			formattedUser.AccountStatus = "Deleted"
			formattedUser.DeletionTime = user.DeletionTime

		} else {
			formattedUser.AccountStatus = "Active"
		}
		// modifying resource type, if the resource type is amdin
		if formattedUser.IsAdmin {
			formattedUser.ResourceType = "Admin"
		}

		// fetch roles and privilege for user
		roles, err := googleWorkSpaceConnector.FetchRolesAndPrivileges(user.CustomerId, user.Id)
		if err != nil {
			return nil, err
		}
		if len(roles.Roles) > 0 {
			formattedUser.Roles = roles.Roles
		}
		if len(roles.Privilege) > 0 {
			formattedUser.Privileges = roles.Privilege
		}

		// fetch groups for the active users, ignoring deleted users
		if cowlibutils.IsEmpty(user.DeletionTime) {
			groups, err := googleWorkSpaceConnector.FetchGroupsForUser(user.Id)
			if err != nil {
				return nil, fmt.Errorf("error while fetching group list for the user - %v :: %v", user.Name.FullName, err)
			}
			if len(groups) > 0 {
				formattedUser.Groups = groups
			}
		}

		formattedUsers = append(formattedUsers, formattedUser)

	}
	return formattedUsers, nil

}

type ErrorVO struct {
	ErrorMessage string `json:"Error"`
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
	IsEnrolledIn2Sv             bool                                  `json:"IsEnrolledIn2Sv"`
	IsEnforcedIn2Sv             bool                                  `json:"IsEnforcedIn2Sv"`
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
