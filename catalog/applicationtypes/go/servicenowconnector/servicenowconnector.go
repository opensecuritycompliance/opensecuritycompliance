package servicenowconnector

import (
	cowlibutils "cowlibrary/utils"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/andrewstuart/servicenow"
)

type SNOW struct {
	UserName string `json:"userName" yaml:"UserName"`
	Password string `json:"password" yaml:"Password"`
}
type OAuth struct {
	ClientID     string `json:"clientID" yaml:"ClientID"`
	ClientSecret string `json:"clientSecret" yaml:"ClientSecret"`
}

type UserDefinedCredentials struct {
	SNOW  SNOW  `json:"sNOW" yaml:"SNOW"`
	OAuth OAuth `json:"oAuth" yaml:"OAuth"`
}

type LinkedApplications struct {
}

type ServiceNowConnector struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"appPort"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
	LinkedApplications     *LinkedApplications     `json:"linkedApplications" yaml:"linkedApplications"`
}

func (thisObj *ServiceNowConnector) Validate() (bool, error) {
	if thisObj.UserDefinedCredentials == nil {
		return false, errors.New("No credentials provided")
	}

	snowErr := thisObj.UserDefinedCredentials.SNOW.ValidateAttributes()
	if snowErr == "" {
		return thisObj.validateBasicAuth()
	}

	oauthErr := thisObj.UserDefinedCredentials.OAuth.ValidateAttributes()
	if oauthErr == "" {
		return thisObj.validateOAuth()
	}

	return false, errors.New("No valid ServiceNow credentials provided")
}

func (snow *SNOW) ValidateAttributes() string {
	var emptyAttributes []string
	errorResultStr := ""
	if snow.UserName == "" {
		emptyAttributes = append(emptyAttributes, "UserName")
	}
	if snow.Password == "" {
		emptyAttributes = append(emptyAttributes, "Password")
	}
	if len(emptyAttributes) > 0 {
		errorResultStr = fmt.Sprintf("Invalid Credentials: %s", strings.Join(emptyAttributes, ", ")+" is empty")
	}
	return errorResultStr
}

func (oauth *OAuth) ValidateAttributes() string {
	var emptyAttributes []string
	errorResultStr := ""
	if oauth.ClientID == "" {
		emptyAttributes = append(emptyAttributes, "ClientID")
	}
	if oauth.ClientSecret == "" {
		emptyAttributes = append(emptyAttributes, "ClientSecret")
	}
	if len(emptyAttributes) > 0 {
		errorResultStr = fmt.Sprintf("Invalid Credentials: %s", strings.Join(emptyAttributes, ", ")+" is empty")
	}
	return errorResultStr
}

func (thisObj *ServiceNowConnector) validateBasicAuth() (bool, error) {
	client := thisObj.GetServiceNowClient()

	_, err := client.GetRecords("sys_user", url.Values{"sysparm_limit": []string{"1"}})
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			return false, errors.New("Invalid AppURL")
		}
		return false, errors.New("Cannot parse response, instance could be in hibernated state")
	}

	return true, nil
}

func (thisObj *ServiceNowConnector) validateOAuth() (bool, error) {
	instance := strings.TrimRight(thisObj.AppURL, "/")

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", thisObj.UserDefinedCredentials.OAuth.ClientID)
	data.Set("client_secret", thisObj.UserDefinedCredentials.OAuth.ClientSecret)

	tokenURL := instance + "/oauth_token.do"

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return false, errors.New("Invalid AppURL")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return false, errors.New("Invalid client_id or client_secret")
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("OAuth failed with status %d", resp.StatusCode)
	}

	return true, nil
}

func (thisObj *ServiceNowConnector) GetServiceNowClient() servicenow.Client {
	return servicenow.Client{
		Instance: thisObj.AppURL,
		Username: thisObj.UserDefinedCredentials.SNOW.UserName,
		Password: thisObj.UserDefinedCredentials.SNOW.Password,
	}
}

func (thisObj *ServiceNowConnector) GetServiceNowUsers(userQuery url.Values) ([]map[string]interface{}, error) {
	serviceNowClient := thisObj.GetServiceNowClient()

	users, err := serviceNowClient.GetUsers(userQuery)
	return users, err
}

func (thisObj *ServiceNowConnector) GetServiceNowRecords(table string, query url.Values) ([]map[string]interface{}, error) {
	serviceNowClient := thisObj.GetServiceNowClient()

	data, err := serviceNowClient.GetRecords(table, query)
	return data, err
}

func (thisObj *ServiceNowConnector) InsertIntoServiceNowTable(table string, obj interface{}, out interface{}) error {
	serviceNowClient := thisObj.GetServiceNowClient()

	err := serviceNowClient.Insert(table, obj, &out)
	return err
}

// return appURL after removing trailing '/'
func (thisObj *ServiceNowConnector) GetAppURL() (string, error) {
	url := thisObj.AppURL
	if cowlibutils.IsEmpty(url) {
		return "", errors.New("AppURL is empty")
	}
	if url[len(url)-1] == '/' {
		return url[:len(url)-1], nil
	}
	return url, nil
}
