package servicenowconnector

import (
	cowlibutils "cowlibrary/utils"
	"errors"
	"net/url"
	"strings"

	"github.com/andrewstuart/servicenow"
)

type SNOW struct {
	UserName string `json:"userName" yaml:"UserName"`
	Password string `json:"password" yaml:"Password"`
}

type UserDefinedCredentials struct {
	SNOW SNOW `json:"sNOW" yaml:"SNOW"`
}

type ServiceNowConnector struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"port"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
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

func (thisObj *ServiceNowConnector) GetServiceNowClient() servicenow.Client {
	return servicenow.Client{
		Instance: thisObj.AppURL,
		Username: thisObj.UserDefinedCredentials.SNOW.UserName,
		Password: thisObj.UserDefinedCredentials.SNOW.Password,
	}
}

func (thisObj *ServiceNowConnector) Validate() (bool, error) {
	username := thisObj.UserDefinedCredentials.SNOW.UserName
	password := thisObj.UserDefinedCredentials.SNOW.Password

	if cowlibutils.IsNotEmpty(username) && cowlibutils.IsNotEmpty(password) {
		serviceNowClient := thisObj.GetServiceNowClient()
		_, err := serviceNowClient.GetRecords("instance", url.Values{})
		if err != nil {
			if strings.Contains(err.Error(), "no such host") {
				return false, errors.New("Invalid AppURL")
			}
			return false, errors.New("Cannot parse response, instance could be in hibernated state")
		}
		return true, nil
	}
	return false, errors.New("Username or password is empty")
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
