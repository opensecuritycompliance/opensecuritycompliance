package compliancecow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

type OAuth struct {
	ClientID     string `json:"clientID" yaml:"ClientID"`
	ClientSecret string `json:"clientSecret" yaml:"ClientSecret"`
}

type UserDefinedCredentials struct {
	OAuth OAuth `json:"oAuth" yaml:"OAuth"`
}

type ComplianceCow struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"port"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
}

func (thisObj *ComplianceCow) Validate() (bool, error) {
	err := thisObj.CheckComplianceCowCredentials()
	if err != nil {
		return false, err
	}
	return true, nil
}

func (thisObj *ComplianceCow) CheckComplianceCowCredentials() error {
	creds := []string{}
	if thisObj.UserDefinedCredentials == nil {
		return fmt.Errorf("UserInputs is empty")
	}
	if thisObj.UserDefinedCredentials.OAuth.ClientID == "" {
		creds = append(creds, "ClientID is empty")
	}
	if thisObj.UserDefinedCredentials.OAuth.ClientSecret == "" {
		creds = append(creds, "ClientSecret is empty")
	}
	if thisObj.AppURL == "" {
		creds = append(creds, "LoginURL is empty")
	}
	if len(creds) > 0 {

		return fmt.Errorf("%v", strings.Join(creds, ","))
	}

	err := thisObj.ValidateComplianceCowCredentials()
	return err
}

func (thisObj *ComplianceCow) GetComplianceCowCredentials() (clientID, clientSecret, loginURL string, err error) {

	err = thisObj.CheckComplianceCowCredentials()
	if err != nil {
		return "", "", "", err
	}
	complianceCow := thisObj.UserDefinedCredentials.OAuth
	clientID = complianceCow.ClientID
	clientSecret = complianceCow.ClientSecret
	loginURL = thisObj.AppURL

	return clientID, clientSecret, loginURL, nil
}

func (thisObj *ComplianceCow) ValidateComplianceCowCredentials() error {
	clientID := thisObj.UserDefinedCredentials.OAuth.ClientID
	clientSecret := thisObj.UserDefinedCredentials.OAuth.ClientSecret
	loginURL := thisObj.AppURL
	statuscode, _, err := FetchComplianceCowAuthToken(clientID, clientSecret, loginURL)
	if err != nil {
		return err
	}
	if statuscode == http.StatusOK {
		return nil
	}
	return errors.New("failed to validate compliancecow oauth2")
}

func FetchComplianceCowAuthToken(clientID, clientSecret, loginURL string) (int, string, error) {
	loginURL = CheckLoginURL(loginURL)
	form := url.Values{}
	form.Add("grant_type", "client_credentials")
	form.Add("client_id", clientID)
	form.Add("client_secret", clientSecret)
	req, err := http.NewRequest(http.MethodPost, loginURL+"api/v1/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return 0, "", err
	}
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	statuscode, resBody, err := httpNewRequest(req, http.StatusOK)
	if err != nil {
		return statuscode, "", err
	}
	auth := ComplianceCowAuthToken{}
	err = json.Unmarshal(resBody, &auth)
	if err != nil {
		return statuscode, "", err
	}
	return statuscode, fmt.Sprintf("%v %v", auth.TokenType, auth.AuthToken), nil
}

func CheckLoginURL(loginURL string) string {
	length := len(loginURL)
	if length > 0 && loginURL[length-1] != '/' {
		loginURL += "/"
	}
	return loginURL
}

func GetStringFromMap(data map[string]interface{}, key string) string {
	if v, ok := data[key]; ok {
		if vString, ok := v.(string); ok {
			return vString
		}
	}
	return ""
}

func httpNewRequest(req *http.Request, statusCode int) (int, []byte, error) {
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			return 0, nil, fmt.Errorf("Invalid URL.")
		} else if strings.Contains(err.Error(), "timeout") {
			return 0, nil, fmt.Errorf("Invalid URL.")
		} else {
			return 0, nil, err
		}
	}
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return res.StatusCode, nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == statusCode {
		return res.StatusCode, resBody, nil
	}
	return res.StatusCode, nil, fmt.Errorf("Invalid ClientID and/or ClientSecret.")
}

func (thisObj *ComplianceCow) SentChannelNotification(ccInfo CCFields) (int, []byte, error) {
	clientID, clientSecret, loginURL, err := thisObj.GetComplianceCowCredentials()
	if err != nil {
		return 0, nil, err
	}
	jsonData, err := json.Marshal(ccInfo.Attachments)
	if err != nil {
		log.Fatalf("Error converting to JSON: %v", err)
	}
	url := CheckLoginURL(loginURL)
	payload := []byte(fmt.Sprintf(`{
		"MessageBody": "%v",
		"MessageHeader":"%v",
		"NotificationChannelInfo": [
			{
				"ChannelType": "bot"
			}
		],
		"UsersToShow": [%v],
		"Attachments" : %v
	}`, ccInfo.NotificationMessageBody, ccInfo.NotificationMessageHeader, strings.Join(ccInfo.Users, ","), string(jsonData)))
	statuscode, authToken, err := FetchComplianceCowAuthToken(clientID, clientSecret, url)
	if err != nil {
		return statuscode, nil, err
	}
	client := resty.New()
	resp, err := client.R().SetHeader("Authorization", authToken).SetBody(payload).Post(url + "api/v1/notification")
	if err != nil {
		return resp.StatusCode(), nil, err
	}
	return resp.StatusCode(), resp.Body(), nil
}

func (thisObj *ComplianceCow) GetRecordAssignee(recordID string) ([]string, []string, error) {

	statusCode, response, err := thisObj.GetAPIResponse(http.MethodGet, fmt.Sprintf("api/v1/workflow-buckets?data_ids=%v", recordID), nil, "")
	if err != nil {
		return nil, nil, err
	}

	if statusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("Request failed with status code: %d, and response: %s", statusCode, string(response))
	}

	recordAssigneeVO := RecordAssigneeVO{}

	err = json.Unmarshal(response, &recordAssigneeVO)
	if err != nil {
		return nil, nil, err
	}

	var userIDs []string
	var userEmailIds []string

	for _, assignee := range recordAssigneeVO.Items {
		userIDs = assignee.UserIds
	}

	statusCode1, response1, err := thisObj.GetAPIResponse(http.MethodGet, "api/v1/users?emails=", nil, "")
	if err != nil {
		return nil, nil, err
	}
	if statusCode1 != 200 {
		return nil, nil, fmt.Errorf("Request failed with status code: %d, and response: %s", statusCode, string(response))
	}

	userVO := UserVO{}
	err = json.Unmarshal(response1, &userVO)
	if err != nil {
		return nil, nil, err
	}

	for _, user := range userVO.Items {
		if slices.Contains(userIDs, user.ID) {
			userEmailIds = append(userEmailIds, user.Emailid)
		}
	}

	return userIDs, userEmailIds, nil

}

func (thisObj *ComplianceCow) GetComplianceCowUserIDs(usersMailIDs string) ([]string, error) {

	statusCode, response, err := thisObj.GetAPIResponse(http.MethodGet, fmt.Sprintf("api/v1/users?emails=%v", usersMailIDs), nil, "")
	if err != nil {
		return nil, err
	}

	if statusCode != 200 {
		return nil, fmt.Errorf("Request failed with status code: %d, and response: %s", statusCode, string(response))
	}

	userVO := UserVO{}
	err = json.Unmarshal(response, &userVO)
	if err != nil {
		return nil, err
	}
	usersMailIDsList := strings.Split(usersMailIDs, ",")

	var userIDsList []string

	for _, user := range userVO.Items {
		if slices.Contains(usersMailIDsList, user.Emailid) {
			userIDsList = append(userIDsList, strconv.Quote(user.ID))
		}
	}
	return userIDsList, nil
}

func (thisObj *ComplianceCow) GetComplianceCowPlanInstanceControlDetails(planInstanceControlID string, planInstanceRunID string) (*ControlVO, error) {

	statusCode, response, err := thisObj.GetAPIResponse(http.MethodGet, fmt.Sprintf("/api/v5/partner/assessment-runs/%v/controls/%v", planInstanceRunID, planInstanceControlID), nil, "")
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("Request failed with status code: %d, and response: %s", statusCode, string(response))
	}

	planInstanceControlDetails := ControlVO{}
	err = json.Unmarshal(response, &planInstanceControlDetails)
	if err != nil {
		return nil, err
	}

	return &planInstanceControlDetails, nil
}

func (thisObj *ComplianceCow) GetAPIResponse(method string, url string, data interface{}, contentType string) (int, []byte, error) {

	clientID, clientSecret, loginURL, err := thisObj.GetComplianceCowCredentials()
	if err != nil {
		return 0, nil, err
	}
	loginURL = CheckLoginURL(loginURL)

	statuscode, authToken, err := FetchComplianceCowAuthToken(clientID, clientSecret, loginURL)
	if err != nil {
		return 0, nil, err
	}

	if statuscode != 200 {
		return 0, nil, fmt.Errorf("invalid credentials")
	}

	client := &http.Client{}

	var body []byte
	if method == http.MethodPost || method == http.MethodPatch {
		body, err = json.Marshal(data)
		if err != nil {
			return 0, nil, err
		}
	}

	loginURL = loginURL + url

	req, err := http.NewRequest(method, loginURL, bytes.NewBuffer(body))
	if err != nil {
		return 0, nil, err
	}

	if method == http.MethodPost || method == http.MethodPatch {
		req.Header.Set("Content-Type", contentType)
	}

	req.Header.Set("Authorization", authToken)

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}

	return resp.StatusCode, body, nil
}

type ApiResponse struct {
	StatusCode int    `json:"status_code"`
	Body       string `json:"body"`
}
type ComplianceCowAuthToken struct {
	TokenType string `json:"tokenType"`
	ExpiresIn int    `json:"expiresIn"`
	AuthToken string `json:"authToken"`
}

type CCFields struct {
	LoginURL                   string           `json:"loginURL"`
	ClientID                   string           `json:"clientId"`
	ClientSecret               string           `json:"clientSecret"`
	AuthToken                  string           `json:"authToken"`
	PlanID                     string           `json:"planId"`
	PlanName                   string           `json:"planName"`
	Displayable                string           `json:"displayable"`
	Alias                      string           `json:"alias"`
	ControlName                string           `json:"controlName"`
	ControlID                  string           `json:"controlId"`
	ActivationStatus           string           `json:"activationStatus"`
	ControlDescription         string           `json:"controlDescription"`
	RuleID                     string           `json:"ruleId"`
	CreateEvidence             bool             `json:"createEvidence"`
	TemplateType               string           `json:"templateType"`
	OwnerType                  string           `json:"ownerType"`
	Type                       string           `json:"type"`
	EvidenceName               string           `json:"evidenceName"`
	FileName                   string           `json:"fileName"`
	IsUploadFlow               string           `json:"isUploadFlow"`
	UserDefinedSynthesizerName string           `json:"userDefinedSynthesizerName"`
	Actions                    []string         `json:"actions"`
	Users                      []string         `json:"users"`
	NotificationMessageHeader  string           `json:"notificationMessageHeader"`
	NotificationMessageBody    string           `json:"notificationMessageBody"`
	Attachments                []FileAttachment `json:"AttachmentsVO"`
}

// FileAttachment :
type FileAttachment struct {
	Name         string
	ContentBytes string
}

type UserVO struct {
	Items []struct {
		CreatedAt         time.Time   `json:"CreatedAt"`
		DeletedAt         interface{} `json:"DeletedAt"`
		DomainID          string      `json:"DomainID"`
		GroupID           string      `json:"GroupID"`
		ID                string      `json:"ID"`
		IsValidated       bool        `json:"IsValidated"`
		LastAccessed      time.Time   `json:"LastAccessed"`
		LastUpdated       string      `json:"LastUpdated"`
		OrgID             string      `json:"OrgID"`
		RoleID            string      `json:"RoleID"`
		RoleName          string      `json:"RoleName"`
		RolesInfo         interface{} `json:"RolesInfo"`
		UpdatedAt         time.Time   `json:"UpdatedAt"`
		UserRoleID        string      `json:"UserRoleID"`
		Emailid           string      `json:"emailid"`
		Status            string      `json:"status"`
		Username          string      `json:"username"`
		Hash              string      `json:"hash,omitempty"`
		Otpgeneratedcount int         `json:"otpgeneratedcount,omitempty"`
		Token             string      `json:"token,omitempty"`
	} `json:"items"`
	TotalItems int `json:"TotalItems"`
	TotalPage  int `json:"TotalPage"`
	Page       int `json:"Page"`
}

type RecordAssigneeVO struct {
	Items []struct {
		ID                   string   `json:"id"`
		WorkflowInstanceID   string   `json:"workflowInstanceId"`
		EvidenceID           string   `json:"evidenceId"`
		DataID               string   `json:"dataId"`
		DataType             string   `json:"dataType"`
		UserIds              []string `json:"userIds"`
		Status               string   `json:"status"`
		UserWorkflowInstance []struct {
			WorkflowInstanceID string `json:"workflowInstanceId"`
			UserID             string `json:"userID"`
			Order              int    `json:"order"`
		} `json:"userWorkflowInstance"`
		CreatedAt time.Time `json:"createdAt"`
		UpdatedAt time.Time `json:"updatedAt"`
		DomainID  string    `json:"domainId"`
		OrgID     string    `json:"orgId"`
		GroupID   string    `json:"groupId"`
	} `json:"items"`
	TotalItems int `json:"TotalItems"`
	TotalPage  int `json:"TotalPage"`
	Page       int `json:"Page"`
}

type ControlVO struct {
	ID               string `json:"id"`
	DomainID         string `json:"domainId"`
	OrgID            string `json:"orgId"`
	GroupID          string `json:"groupId"`
	ParentControlID  string `json:"parentControlId"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	Displayable      string `json:"displayable"`
	Alias            string `json:"alias"`
	Priority         string `json:"priority"`
	Stage            string `json:"stage"`
	Status           string `json:"status"`
	ActivationStatus string `json:"activationStatus"`
	Tags             struct {
		Evidence             []string `json:"evidence"`
		HasAutomaticEvidence []string `json:"hasAutomaticEvidence"`
		HasRecords           []string `json:"hasRecords"`
	} `json:"tags"`
	CnPlanID                    string    `json:"cnPlanId"`
	ConfigID                    string    `json:"configId"`
	UpdatedAt                   time.Time `json:"updatedAt"`
	CreatedAt                   time.Time `json:"createdAt"`
	IsPreRequisite              bool      `json:"isPreRequisite"`
	ControlID                   string    `json:"controlId"`
	PlanInstanceID              string    `json:"planInstanceId"`
	CnPlanExecutionID           string    `json:"cnPlanExecutionId"`
	InitiatedBy                 string    `json:"initiatedBy"`
	Started                     time.Time `json:"started"`
	Ended                       time.Time `json:"ended"`
	CnControlExecutionStartTime time.Time `json:"cnControlExecutionStartTime"`
	CnControlExecutionEndTime   time.Time `json:"cnControlExecutionEndTime"`
	CnSynthesizerStartTime      time.Time `json:"cnSynthesizerStartTime"`
	CnSynthesizerEndTime        time.Time `json:"cnSynthesizerEndTime"`
	Evidences                   []struct {
		ID                           string `json:"id"`
		DomainID                     string `json:"domainId"`
		OrgID                        string `json:"orgId"`
		GroupID                      string `json:"groupId"`
		Name                         string `json:"name"`
		Description                  string `json:"description"`
		FileName                     string `json:"fileName"`
		Type                         string `json:"type"`
		CreatedAt                    string `json:"createdAt"`
		UpdatedAt                    string `json:"updatedAt"`
		ComplianceWeight             int    `json:"complianceWeight__"`
		UserSelectedComplianceWeight int    `json:"userSelectedComplianceWeight__"`
		UserDefinedSynthesizerName   string `json:"userDefinedSynthesizerName"`
		PlanInstanceControlID        string `json:"planInstanceControlId"`
		Status                       string `json:"status"`
		ProcessingError              string `json:"processingError,omitempty"`
		ComplianceStatus             string `json:"complianceStatus__,omitempty"`
		UserSelectedComplianceStatus string `json:"userSelectedComplianceStatus__,omitempty"`
		EvidenceFileInfos            struct {
			TotalRecords int `json:"totalRecords,omitempty"`
			TotalColumns int `json:"totalColumns,omitempty"`
		} `json:"evidenceFileInfos,omitempty"`
	} `json:"evidences"`
	Inputs []struct {
		CnControlID string `json:"cnControlID"`
		Variables   struct {
			GroupStatus string `json:"GroupStatus"`
			Groups      string `json:"Groups"`
			Region      string `json:"Region"`
			RoleStatus  string `json:"RoleStatus"`
			Roles       string `json:"Roles"`
			UserStatus  string `json:"UserStatus"`
			Users       string `json:"Users"`
		} `json:"Variables"`
		Files struct {
			MFARecommendationFile struct {
				FileName    string `json:"FileName"`
				FileContent any    `json:"FileContent"`
				FileHash    string `json:"FileHash"`
			} `json:"MFARecommendationFile"`
		} `json:"Files"`
	} `json:"inputs"`
	ExecutionStatus              string    `json:"executionStatus"`
	DueDate                      string    `json:"dueDate"`
	DueDateTime                  time.Time `json:"dueDateTime"`
	CheckedOut                   bool      `json:"checkedOut"`
	HasOwnAttributeValues        bool      `json:"hasOwnAttributeValues"`
	ComplianceStatus             string    `json:"complianceStatus__"`
	CompliancePCT                int       `json:"compliancePCT__"`
	ComplianceWeight             int       `json:"complianceWeight__"`
	UserSelectedComplianceStatus string    `json:"userSelectedComplianceStatus__"`
	UserSelectedComplianceWeight int       `json:"userSelectedComplianceWeight__"`
	IsOverriden                  bool      `json:"isOverriden"`
	GroupedDisplayables          []string  `json:"groupedDisplayables"`
	AssignmentStack              []any     `json:"assignmentStack"`
	ScoreVersioningTimeStamp     string    `json:"scoreVersioningTimeStamp"`
	WorkflowErrors               struct {
		Error string `json:"error"`
	} `json:"workflowErrors"`
}
