package jiracloud

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	cowlibutils "cowlibrary/utils"

	"github.com/andygrunwald/go-jira"
	"github.com/dmnlk/stringUtils"
	"github.com/go-resty/resty/v2"
)

type BasicAuthentication struct {
	UserName string `json:"userName" yaml:"UserName"`
	Password string `json:"password" yaml:"Password"`
}

type UserDefinedCredentials struct {
	BasicAuthentication BasicAuthentication `json:"basicAuthentication" yaml:"BasicAuthentication"`
}

type JiraCloud struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"port"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
}

func (thisObj *JiraCloud) Validate() (bool, error) {

	if cowlibutils.IsEmpty(thisObj.AppURL) {
		return false, fmt.Errorf("Invalid url")
	}
	credentials := thisObj.UserDefinedCredentials.BasicAuthentication
	if cowlibutils.IsEmpty(credentials.UserName) || cowlibutils.IsEmpty(credentials.Password) {
		return false, fmt.Errorf("Invalid username or password")
	}
	return thisObj.isValidCredentials()
}

/*
The go-jira library does not handle most authentication directly.Instead, authentication should be handled within an http.Client.
That client can then be passed into the NewClient function when creating a jira client.
*/
func (thisObj *JiraCloud) isValidCredentials() (bool, error) {
	client, err := thisObj.CreateNewClient()
	if err != nil {
		return false, err
	}
	_, resp, err := client.User.GetSelf()
	if resp != nil && resp.StatusCode == http.StatusUnauthorized {
		return false, errors.New("Invalid UserName and/or Password.")
	} else if resp != nil && resp.StatusCode == 404 || err != nil && strings.Contains(err.Error(), "No response returned") {
		return false, errors.New("Invalid URL.")
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (thisObj *JiraCloud) CreateNewClient() (*jira.Client, error) {

	tp := jira.BasicAuthTransport{
		Username: thisObj.UserDefinedCredentials.BasicAuthentication.UserName,
		Password: thisObj.UserDefinedCredentials.BasicAuthentication.Password,
	}
	tp.Transport = http.DefaultTransport
	tp.Transport.(*http.Transport).DisableCompression = true
	jiraClient, err := jira.NewClient(tp.Client(), thisObj.AppURL)
	if err != nil {
		return nil, err
	}
	return jiraClient, nil
}

func (thisObj *JiraCloud) CreateNewTicket(ticketDetail JiraTicket) (*jira.Issue, error) {

	if err := validateTicketDetails(ticketDetail); err != nil {
		return nil, err
	}

	jiraClient, err := thisObj.CreateNewClient()
	if err != nil {
		return nil, err
	}
	issue := jira.Issue{
		Fields: &jira.IssueFields{

			Description: ticketDetail.Description,
			Type: jira.IssueType{
				Name: ticketDetail.Issuetype,
			},
			Project: jira.Project{
				Key: ticketDetail.Project,
			},
			Summary: ticketDetail.Summary,

			Assignee: &jira.User{
				AccountID: ticketDetail.AssigneeId,
			},
			Reporter: &jira.User{
				AccountID: ticketDetail.ReporterId,
			},
			Priority: &jira.Priority{
				Name: ticketDetail.Priority,
			},
		},
	}
	issueCreated, response, err := jiraClient.Issue.Create(&issue)
	if err != nil {
		if response != nil && response.StatusCode == 400 {
			if err := json.NewDecoder(response.Body).Decode(&apiError); err == nil {
				for _, errorMessage := range apiError.Errors {
					if errorMessage == fmt.Sprintf("No project could be found with key '%s'.", ticketDetail.Project) || errorMessage == fmt.Sprintf("Specify a valid project ID or key") {
						return nil, fmt.Errorf("The specified project name (\"Project\" = \"%s\") doesn't exist, please check.", ticketDetail.Project)
					}
				}
			}
		}
		return nil, err
	}
	return issueCreated, nil

}

func (thisObj *JiraCloud) FindUser(user string) ([]jira.User, error) {

	var userDetails []jira.User
	if stringUtils.IsEmpty(user) {
		return userDetails, fmt.Errorf("Empty user")
	}
	jiraClient, err := thisObj.CreateNewClient()
	if err != nil {
		return userDetails, err
	}
	response, _, err := jiraClient.User.Find(user)
	if err != nil {
		return userDetails, err
	}
	return response, nil

}

func (thisObj *JiraCloud) GetSelf(user string) (*jira.User, error) {

	var userDetails *jira.User
	if stringUtils.IsEmpty(user) {
		return userDetails, fmt.Errorf("Empty user")
	}
	client, err := thisObj.CreateNewClient()
	if err != nil {
		return userDetails, err
	}
	userDetails, resp, err := client.User.GetSelf()
	if resp != nil && resp.StatusCode == http.StatusUnauthorized {
		return userDetails, errors.New("Invalid jira credential")
	} else if err != nil {
		return userDetails, err
	}
	return userDetails, nil

}

func (thisObj *JiraCloud) GetTicket(ticketId string) (*jira.Issue, error) {

	var issueDetails *jira.Issue
	if stringUtils.IsEmpty(ticketId) {
		return issueDetails, fmt.Errorf("Empty ticket id")
	}
	jiraClient, err := thisObj.CreateNewClient()
	if err != nil {
		return issueDetails, err
	}
	response, _, err := jiraClient.Issue.Get(ticketId, nil)
	if err != nil {
		return issueDetails, err
	}
	return response, nil

}

func (thisObj *JiraCloud) AddAttachmentWithJiraTicket(ticketId string, file io.Reader, fileName string) (*[]jira.Attachment, error) {

	if stringUtils.IsEmpty(ticketId) {
		return nil, fmt.Errorf("Ticket Id can't be Empty")
	}
	jiraClient, err := thisObj.CreateNewClient()
	if err != nil {
		return nil, err
	}

	attachment, response, err := jiraClient.Issue.PostAttachment(ticketId, file, fileName)
	if err != nil {
		return nil, fmt.Errorf("Failed to attach the file: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(response.Body)
		return nil, fmt.Errorf("Failed to attach the file: received %d status code, body: %s", response.StatusCode, string(bodyBytes))
	}

	return attachment, nil
}

func validateTicketDetails(ticketDetail JiraTicket) error {
	if cowlibutils.IsEmpty(ticketDetail.Issuetype) {
		return errors.New("Issue type is empty. Issue type must be valid for ticket creation")
	}
	if cowlibutils.IsEmpty(ticketDetail.Description) {
		return errors.New("Description is empty. Description must be valid for ticket creation")
	}
	if cowlibutils.IsEmpty(ticketDetail.Summary) {
		return errors.New("Summary is empty. Summary must be valid for ticket creation")
	}
	if cowlibutils.IsEmpty(ticketDetail.AssigneeId) {
		return errors.New("AssigneeId is empty")
	}
	if cowlibutils.IsEmpty(ticketDetail.ReporterId) {
		return errors.New("ReporterId is empty")
	}
	if cowlibutils.IsEmpty(ticketDetail.Priority) {
		return errors.New("Priority is empty")
	}
	return nil
}

func GetJiraAPIResponse(apiConfig JiraApiCallConfig, responseStruct interface{}) (_ []byte, err error) {

	if stringUtils.IsEmpty(apiConfig.Method) || stringUtils.IsEmpty(apiConfig.Url) {
		return nil, errors.New("Invalid request")
	}

	url := apiConfig.Url
	var response *resty.Response
	var clientWithHeaders *resty.Request

	if responseStruct != nil {
		clientWithHeaders = resty.New().R().SetHeaders(apiConfig.Headers).SetResult(responseStruct)
	} else {
		clientWithHeaders = resty.New().R().SetHeaders(apiConfig.Headers)
	}

	if apiConfig.Method == http.MethodPost || apiConfig.Method == http.MethodPut {
		if apiConfig.Body == nil {
			return nil, errors.New("Invalid requestBody")
		}
		clientWithHeaders.SetBody(apiConfig.Body)
	}

	switch apiConfig.Method {
	case http.MethodPut:
		response, err = clientWithHeaders.Put(url)
	case http.MethodGet:
		response, err = clientWithHeaders.Get(url)
	case http.MethodPost:
		response, err = clientWithHeaders.Post(url)
	default:
		return nil, errors.New("Unsupported HTTP method")
	}

	if err != nil {
		return nil, err
	}

	// success response
	if (apiConfig.Method == http.MethodGet && response.StatusCode() == http.StatusOK) ||
		(apiConfig.Method == http.MethodPost && (response.StatusCode() == http.StatusCreated || response.StatusCode() == http.StatusOK)) ||
		(apiConfig.Method == http.MethodPut && response.StatusCode() == http.StatusOK) {
		return response.Body(), nil
	}

	return nil, err

}

type JiraApiCallConfig struct {
	Method  string            `json:"method"`
	Url     string            `json:"url"`
	Body    interface{}       `json:"body"`
	Headers map[string]string `json:"headers"`
}

type JiraTicket struct {
	Description string `json:"Description"`
	Issuetype   string `json:"Issuetype"`
	Project     string `json:"Project"`
	Summary     string `json:"Summary"`
	AssigneeId  string `json:"AssigneeId"`
	ReporterId  string `json:"Reporter"`
	Priority    string `json:"Priority"`
}

var apiError struct {
	ErrorMessages []string          `json:"errorMessages"`
	Errors        map[string]string `json:"errors"`
}
