package googleworkspaceappconnector

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"

	cowlibutils "cowlibrary/utils"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
	admin "google.golang.org/api/admin/directory/v1"
	reports "google.golang.org/api/admin/reports/v1"

	"google.golang.org/api/option"
)

const (
	SERVICE_ACCOUNT_FILE_NAME = "ServiceAccountCredential.json"
)

type GoogleWorkSpace struct {
	UserEmail             string `json:"userEmail" yaml:"UserEmail"`
	ServiceAccountKeyFile string `json:"serviceAccountKeyFile" yaml:"ServiceAccountKeyFile"`
}

type UserDefinedCredentials struct {
	GoogleWorkSpace GoogleWorkSpace `json:"googleWorkSpace" yaml:"GoogleWorkSpace"`
}

type GoogleWorkSpaceAppConnector struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"port"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
}

func (thisObj *GoogleWorkSpaceAppConnector) ValidateAttributes() string {

	var emptyAttributes []string
	googleWorkSpaceCredentials := thisObj.UserDefinedCredentials.GoogleWorkSpace
	errorResultStr := ""
	if cowlibutils.IsEmpty(googleWorkSpaceCredentials.UserEmail) {
		emptyAttributes = append(emptyAttributes, "UserEmail")
	}
	if cowlibutils.IsEmpty(googleWorkSpaceCredentials.ServiceAccountKeyFile) {
		emptyAttributes = append(emptyAttributes, "ServiceAccountKeyFile")
	}
	if len(emptyAttributes) > 0 {
		errorResultStr = fmt.Sprintf("Invalid Credentials: %s", strings.Join(emptyAttributes, ", ")+" is empty")
	}
	return errorResultStr

}

func (thisObj *GoogleWorkSpaceAppConnector) Validate() (bool, error) {

	if errMsg := thisObj.ValidateAttributes(); cowlibutils.IsNotEmpty(errMsg) {
		return false, fmt.Errorf(errMsg)
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(thisObj.UserDefinedCredentials.GoogleWorkSpace.UserEmail) {
		return false, fmt.Errorf("Invalid 'UserEmail'")
	}

	service, err := thisObj.CreateAdminService(admin.AdminDirectoryDomainReadonlyScope)
	if err != nil {
		return false, fmt.Errorf("Failed to create application: Service configuration error")
	}
	/*
	  Here validating app by fetching domain details.
	  hence adding the scope AdminDirectoryDomainReadonlyScope - "https://www.googleapis.com/auth/admin.directory.domain.readonly"
	  in Domain-wide Delegation will be mandatory for validating application

	  "my_customer" -  alias to represent account's `customerId`
	*/
	_, err = service.Domains.Get("my_customer", thisObj.GetDomainName()).Do()
	if err != nil {
		return false, fmt.Errorf("Invalid 'UserEmail' or 'ServiceAccountKeyFile'")
	}

	return true, nil
}

func (thisObj *GoogleWorkSpaceAppConnector) GetServiceConfigDetails(scope string) (oauth2.TokenSource, context.Context, error) {

	ctx := context.Background()
	config, err := thisObj.CreateConfig(scope)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create JWT config ::  %v", err)
	}
	googleWorkSpaceCredentials := thisObj.UserDefinedCredentials.GoogleWorkSpace
	config.Subject = googleWorkSpaceCredentials.UserEmail
	// Create a token source
	tokenSource := config.TokenSource(ctx)
	return tokenSource, ctx, nil
}

func (thisObj *GoogleWorkSpaceAppConnector) CreateAdminService(scope string) (*admin.Service, error) {

	tokenSource, context, err := thisObj.GetServiceConfigDetails(scope)
	if err != nil {
		return nil, fmt.Errorf("Failed to create service : %v", err)
	}
	// Create a admin service with the token source
	service, err := admin.NewService(context, option.WithTokenSource(tokenSource))
	if err != nil {
		return nil, fmt.Errorf("Failed to create service : %v", err)
	}
	return service, nil

}

func (thisObj *GoogleWorkSpaceAppConnector) CreateReportService(scope string) (*reports.Service, error) {

	tokenSource, context, err := thisObj.GetServiceConfigDetails(scope)
	if err != nil {
		return nil, fmt.Errorf("Failed to create service :: %v", err)
	}
	// Create a report service with the token source
	service, err := reports.NewService(context, option.WithTokenSource(tokenSource))
	if err != nil {
		return nil, fmt.Errorf("Failed to create service :: %v", err)
	}
	return service, nil

}

func (thisObj *GoogleWorkSpaceAppConnector) CreateConfig(scope string) (*jwt.Config, error) {

	googleWorkSpaceCredentials := thisObj.UserDefinedCredentials.GoogleWorkSpace
	serviceAccountJSONKeyDecoded, err := thisObj.DecodeServiceAccountJson(googleWorkSpaceCredentials.ServiceAccountKeyFile)
	if err != nil {
		return nil, err
	}

	err = os.WriteFile(SERVICE_ACCOUNT_FILE_NAME, serviceAccountJSONKeyDecoded, 0644)
	if err != nil {
		return nil, fmt.Errorf("Failed to create a service account credential file for internal handling :: %v", err)
	}
	defer os.Remove(SERVICE_ACCOUNT_FILE_NAME)

	jsonCredentials, err := os.ReadFile(SERVICE_ACCOUNT_FILE_NAME)
	if err != nil {
		return nil, fmt.Errorf("Failed to read service credential account file ::  %v", err)
	}

	// Create a JWT config from JSON credentials
	config, err := google.JWTConfigFromJSON(jsonCredentials, scope)
	if err != nil {
		return nil, fmt.Errorf("Failed to create JWT config ::  %v", err)
	}

	return config, nil

}

func (thisObj *GoogleWorkSpaceAppConnector) ListUsers() ([]*admin.User, error) {

	var userList []*admin.User
	service, err := thisObj.CreateAdminService(admin.AdminDirectoryUserReadonlyScope)
	if err != nil {
		return nil, err
	}
	nextPageToken := ""
	for {
		users, err := service.Users.List().Domain(thisObj.GetDomainName()).PageToken(nextPageToken).Do()
		if err != nil {
			return nil, fmt.Errorf("Error while fetching user list :: %v", err)
		}
		userList = append(userList, users.Users...)
		nextPageToken = users.NextPageToken
		if cowlibutils.IsEmpty(nextPageToken) {
			break
		}
	}
	return userList, nil
}

func (thisObj *GoogleWorkSpaceAppConnector) ListGroups() ([]*admin.Group, error) {

	var groupList []*admin.Group
	service, err := thisObj.CreateAdminService(admin.AdminDirectoryGroupReadonlyScope)
	if err != nil {
		return nil, err
	}
	nextPageToken := ""
	for {
		groupDetails, err := service.Groups.List().Domain(thisObj.GetDomainName()).PageToken(nextPageToken).Do()
		if err != nil {
			return groupList, fmt.Errorf("Error while fetching groupList :: %v", err)
		}
		groupList = append(groupList, groupDetails.Groups...)
		nextPageToken = groupDetails.NextPageToken
		if cowlibutils.IsEmpty(nextPageToken) {
			break
		}
	}

	return groupList, nil
}

func (thisObj *GoogleWorkSpaceAppConnector) ListRoles() ([]*admin.RoleAssignment, error) {

	var roleList []*admin.RoleAssignment
	service, err := thisObj.CreateAdminService(admin.AdminDirectoryRolemanagementReadonlyScope)
	if err != nil {
		return nil, err
	}
	nextPageToken := ""
	for {
		roleDetails, err := service.RoleAssignments.List("my_customer").PageToken(nextPageToken).Do()
		if err != nil {
			return roleList, fmt.Errorf("Error while fetching roleList: %v", err)
		}
		roleList = append(roleList, roleDetails.Items...)
		nextPageToken = roleDetails.NextPageToken
		if cowlibutils.IsEmpty(nextPageToken) {
			break
		}
	}

	return roleList, nil
}

func (thisObj *GoogleWorkSpaceAppConnector) ListDeletedUsers() ([]*admin.User, error) {

	var userList []*admin.User
	service, err := thisObj.CreateAdminService(admin.AdminDirectoryUserReadonlyScope)
	if err != nil {
		return nil, err
	}
	nextPageToken := ""
	for {
		users, err := service.Users.List().Domain(thisObj.GetDomainName()).PageToken(nextPageToken).ShowDeleted("true").Do()
		if err != nil {
			return userList, fmt.Errorf("Error while fetching userList :: %v", err)
		}
		userList = append(userList, users.Users...)
		nextPageToken = users.NextPageToken
		if cowlibutils.IsEmpty(nextPageToken) {
			break
		}
	}

	return userList, nil
}

func (thisObj *GoogleWorkSpaceAppConnector) FetchRoles(customerId string, userId string) ([]*admin.Role, error) {

	var roles []*admin.Role
	service, err := thisObj.CreateAdminService(admin.AdminDirectoryRolemanagementReadonlyScope)
	if err != nil {
		return nil, err
	}
	nextPageToken := ""
	for {
		roleDetails, err := service.Roles.List(customerId).Do()
		if err != nil {
			return nil, fmt.Errorf("Error while fetching role details: %v", err)
		}
		roles = append(roles, roleDetails.Items...)
		nextPageToken = roleDetails.NextPageToken
		if cowlibutils.IsEmpty(nextPageToken) {
			break
		}
	}
	return roles, nil

}

func (thisObj *GoogleWorkSpaceAppConnector) FetchRoleAssignments(customerId string, userId string) ([]*admin.RoleAssignment, error) {

	var roleAssigments []*admin.RoleAssignment
	service, err := thisObj.CreateAdminService(admin.AdminDirectoryRolemanagementReadonlyScope)
	if err != nil {
		return nil, err
	}
	nextPageToken := ""
	for {
		roleAssignmentDetails, err := service.RoleAssignments.List(customerId).Do()
		if err != nil {
			return nil, fmt.Errorf("Error while fetching role assignment details: %v", err)
		}
		roleAssigments = append(roleAssigments, roleAssignmentDetails.Items...)
		nextPageToken = roleAssignmentDetails.NextPageToken
		if cowlibutils.IsEmpty(nextPageToken) {
			break
		}
	}
	return roleAssigments, nil

}

func (thisObj *GoogleWorkSpaceAppConnector) FetchRolesAndPrivileges(customerId string, userId string) (RoleAndPrivilege, error) {

	var roles []string
	var privileges []string
	var roleAndPrivilege RoleAndPrivilege
	privilegeTrackerMap := map[string]bool{}

	roleDetails, err := thisObj.FetchRoles(customerId, userId)
	if err != nil {
		return roleAndPrivilege, err
	}

	roleAssignments, err := thisObj.FetchRoleAssignments(customerId, userId)
	if err != nil {
		return roleAndPrivilege, err
	}

	for _, role := range roleDetails {
		for _, roleAssignment := range roleAssignments {
			if roleAssignment.AssignedTo == userId && role.RoleId == roleAssignment.RoleId {
				roles = append(roles, role.RoleName)
				for _, privilege := range role.RolePrivileges {
					// ignore duplicate privilages
					if !privilegeTrackerMap[privilege.PrivilegeName] {
						privileges = append(privileges, privilege.PrivilegeName)
					}
					privilegeTrackerMap[privilege.PrivilegeName] = true
				}
			}
		}
	}

	roleAndPrivilege.Roles = roles
	roleAndPrivilege.Privilege = privileges
	return roleAndPrivilege, nil

}
func (thisObj *GoogleWorkSpaceAppConnector) FetchGroups(userId string) ([]*admin.Group, error) {

	var groups []*admin.Group
	service, err := thisObj.CreateAdminService(admin.AdminDirectoryGroupReadonlyScope)
	if err != nil {
		return nil, err
	}
	nextPageToken := ""
	for {
		groupDetails, err := service.Groups.List().UserKey(userId).Do()
		if err != nil {
			return nil, err
		}
		groups = append(groups, groupDetails.Groups...)
		nextPageToken = groupDetails.NextPageToken
		if cowlibutils.IsEmpty(nextPageToken) {
			break
		}
	}
	return groups, nil

}

func (thisObj *GoogleWorkSpaceAppConnector) FetchGroupsForUser(userId string) ([]GroupVO, error) {

	var groupList []GroupVO

	service, err := thisObj.CreateAdminService(admin.AdminDirectoryGroupMemberReadonlyScope)
	if err != nil {
		return nil, err
	}
	groups, err := thisObj.FetchGroups(userId)
	if err != nil {
		return nil, err
	}

	for _, group := range groups {
		member, err := service.Members.Get(group.Email, userId).Do()
		if err != nil {
			return nil, err
		}
		groupVO := GroupVO{
			GroupName:  group.Name,
			GroupEmail: group.Email,
			Role:       member.Role,
			Status:     member.Status,
		}
		groupList = append(groupList, groupVO)
	}

	return groupList, nil

}

func (thisObj *GoogleWorkSpaceAppConnector) ListActivities(startTime string, endTime string, applicationName string) ([]UserEventDetails, error) {

	var usersWithEventDetails []UserEventDetails
	service, err := thisObj.CreateReportService(reports.AdminReportsAuditReadonlyScope)
	if err != nil {
		return nil, err
	}
	nextPageToken := ""
	for {
		// Use "all" to get activities for all users
		activityList, err := service.Activities.List("all", applicationName).StartTime(startTime).EndTime(endTime).Do()
		if err != nil {
			return nil, err
		}

		for _, activity := range activityList.Items {

			userWithEventDetails := UserEventDetails{
				// user level data fetching
				UserId:    activity.Actor.ProfileId,
				UserEmail: activity.Actor.Email,
				EventTime: activity.Id.Time,
			}

			for _, event := range activity.Events {

				// event level data fetching
				userWithEventDetails.ResourceName = event.Name
				userWithEventDetails.ResourceType = event.Type
				userWithEventDetails.Parameters = event.Parameters
				userWithEventDetails.System = "google_workspace"
				userWithEventDetails.Source = "compliancecow"

				usersWithEventDetails = append(usersWithEventDetails, userWithEventDetails)
			}

		}
		nextPageToken = activityList.NextPageToken
		if cowlibutils.IsEmpty(nextPageToken) {
			break
		}
	}
	return usersWithEventDetails, nil
}

func (thisObj *GoogleWorkSpaceAppConnector) ListUsageReport(date string) ([]UserUsageDetails, error) {

	var userUsageReports []UserUsageDetails
	service, err := thisObj.CreateReportService(reports.AdminReportsUsageReadonlyScope)
	if err != nil {
		return nil, err
	}

	nextPageToken := ""

	for {
		userUsageDetails, err := service.UserUsageReport.Get("all", date).Do()
		if err != nil {
			return nil, err
		}
		userUsageReport := UserUsageDetails{}
		for _, report := range userUsageDetails.UsageReports {
			userUsageReport.Source = "compliancecow"
			userUsageReport.System = "google_workspace"
			userUsageReport.ResourceName = report.Entity.UserEmail
			userUsageReport.ResourceId = report.Entity.ProfileId
			userUsageReport.CustomerId = report.Entity.CustomerId
			userUsageReport.Parameters = report.Parameters
			userUsageReport.Date = date
		}
		userUsageReports = append(userUsageReports, userUsageReport)
		nextPageToken = userUsageDetails.NextPageToken
		if cowlibutils.IsEmpty(nextPageToken) {
			break
		}
	}
	return userUsageReports, nil
}

func (thisObj *GoogleWorkSpaceAppConnector) ListMobileDevices() ([]MobileDevice, error) {

	var mobileDevices []MobileDevice
	service, err := thisObj.CreateAdminService(admin.AdminDirectoryDeviceMobileReadonlyScope)
	if err != nil {
		return nil, err
	}
	customerID, err := thisObj.getCustomerID()
	if err != nil {
		return nil, fmt.Errorf("Error while fetching customer id :: %v", err)
	}
	nextPageToken := ""
	for {
		// Set the nextPageToken if it's not the first page
		listCall := service.Mobiledevices.List(customerID)
		if nextPageToken != "" {
			listCall.PageToken(nextPageToken)
		}

		// Make the API call to fetch the devices.
		devices, err := listCall.Do()
		if err != nil {
			return nil, fmt.Errorf("Error while fetching mobile devices :: %v", err)
		}

		for _, device := range devices.Mobiledevices {
			mobileDevice := MobileDevice{}
			mobileDevice.System = "google_workspace"
			mobileDevice.Source = "compliancecow"
			mobileDevice.ResourceId = device.DeviceId
			mobileDevice.UserName = device.Name
			mobileDevice.DeviceCompromisedStatus = device.DeviceCompromisedStatus
			mobileDevice.DevicePasswordStatus = device.DevicePasswordStatus
			mobileDevice.FirstSync = device.FirstSync
			mobileDevice.LastSync = device.LastSync
			mobileDevice.OS = device.Os
			mobileDevice.Privilege = device.Privilege
			mobileDevice.ResourceType = device.Type
			mobileDevice.Status = device.Status
			mobileDevice.UserEmail = device.Email

			mobileDevices = append(mobileDevices, mobileDevice)
		}

		nextPageToken = devices.NextPageToken
		if cowlibutils.IsEmpty(nextPageToken) {
			break
		}
	}
	return mobileDevices, nil

}

func (thisObj *GoogleWorkSpaceAppConnector) getCustomerID() (string, error) {

	service, err := thisObj.CreateAdminService(admin.AdminDirectoryUserReadonlyScope)
	if err != nil {
		return "", err
	}
	// Search for the user by email
	user, err := service.Users.Get(thisObj.UserDefinedCredentials.GoogleWorkSpace.UserEmail).Do()
	if err != nil {
		return "", err
	}
	return user.CustomerId, nil

}

func (thisObj *GoogleWorkSpaceAppConnector) GetDomainName() string {

	googleWorkSpaceCredentials := thisObj.UserDefinedCredentials.GoogleWorkSpace
	splitedValues := strings.Split(googleWorkSpaceCredentials.UserEmail, "@")
	if len(splitedValues) > 0 {
		return splitedValues[1]
	}
	return ""

}

func (thisObj *GoogleWorkSpaceAppConnector) DecodeServiceAccountJson(serviceAccountJSONKeyEncoded string) ([]byte, error) {

	serviceAccountJSONKeyDecoded, err := base64.StdEncoding.DecodeString(serviceAccountJSONKeyEncoded)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode service account credential :: %v", err)
	}
	return serviceAccountJSONKeyDecoded, nil
}

type GroupVO struct {
	GroupName  string `json:"groupName"`
	GroupEmail string `json:"groupEmailID"`
	Role       string `json:"role"`
	Status     string `json:"status"`
}

type RoleAndPrivilege struct {
	Roles     []string `json:"Roles"`
	Privilege []string `json:"Privilege"`
}

type UserEventDetails struct {
	System       string                              `json:"System"`
	Source       string                              `json:"Source"`
	ResourceType string                              `json:"ResourceType"`
	ResourceName string                              `json:"ResourceName"`
	UserId       string                              `json:"UserId"`
	UserEmail    string                              `json:"UserEmail"`
	Parameters   []*reports.ActivityEventsParameters `json:"parameters,omitempty"`
	EventTime    string                              `json:"EventTime"`
}

type UserUsageDetails struct {
	System       string                           `json:"System"`
	Source       string                           `json:"Source"`
	ResourceId   string                           `json:"ResourceId"`
	ResourceName string                           `json:"ResourceName"`
	CustomerId   string                           `json:"CustomerId"`
	Parameters   []*reports.UsageReportParameters `json:"parameters,omitempty"`
	Date         string                           `json:"Date"`
}

type MobileDevice struct {
	System                  string   `json:"System"`
	Source                  string   `json:"Source"`
	ResourceId              string   `json:"ResourceId"`
	ResourceType            string   `json:"ResourceType"`
	Status                  string   `json:"Status"`
	DeviceCompromisedStatus string   `json:"DeviceCompromisedStatus"`
	DevicePasswordStatus    string   `json:"DevicePasswordStatus"`
	FirstSync               string   `json:"FirstSync"`
	LastSync                string   `json:"LastSync"`
	OS                      string   `json:"OS"`
	Privilege               string   `json:"Privilege"`
	UserEmail               []string `json:"UserEmail"`
	UserName                []string `json:"UserName"`
}
