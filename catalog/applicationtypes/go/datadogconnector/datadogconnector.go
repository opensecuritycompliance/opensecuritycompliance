package datadogconnector

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type DataDogCred struct {
	APIKey         string `json:"aPIKey" yaml:"APIKey"`
	ApplicationKey string `json:"applicationKey" yaml:"ApplicationKey"`
}

type UserDefinedCredentials struct {
	DataDogCred DataDogCred `json:"dataDogCred" yaml:"DataDogCred"`
}

type DatadogConnector struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"appPort"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
}

func (thisObj *DatadogConnector) Validate() (bool, error) {

	url, errStr := thisObj.getAppURL()
	if errStr != "" {
		return false, errors.New(errStr)
	}

	errStr = thisObj.ValidateAttributes()
	if errStr != "" {
		return false, errors.New(errStr)
	}

	req, err := http.NewRequest("GET", url+"/api/v2/logs/events", nil)
	if err != nil {
		return false, fmt.Errorf("Error creating request: %w", err)
	}

	if thisObj.UserDefinedCredentials != nil {
		req.Header.Add("DD-API-KEY", thisObj.UserDefinedCredentials.DataDogCred.APIKey)
		req.Header.Add("DD-APPLICATION-KEY", thisObj.UserDefinedCredentials.DataDogCred.ApplicationKey)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Accept", "application/json")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, errors.New("Invalid URL, please check.")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == 403 {
		return false, errors.New("API Key or Application Key is invalid, please check")
	} else if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("An unknown error has occurred, response status code: %v", resp.StatusCode)
	}

	return true, nil
}

func (thisObj *DatadogConnector) ValidateAttributes() string {
	var emptyAttributes []string
	errorResultStr := ""
	if thisObj.UserDefinedCredentials.DataDogCred.APIKey == "" {
		emptyAttributes = append(emptyAttributes, "APIKey")
	}
	if thisObj.UserDefinedCredentials.DataDogCred.ApplicationKey == "" {
		emptyAttributes = append(emptyAttributes, "ApplicationKey")
	}
	if len(emptyAttributes) > 0 {
		errorResultStr = fmt.Sprintf("Invalid Credentials: %s", strings.Join(emptyAttributes, ", ")+" is empty")
	}
	return errorResultStr
}

func (thisObj *DatadogConnector) getAppURL() (string, string) {
	url := thisObj.AppURL
	if url == "" {
		return "", "AppURL is empty"
	}

	// remove trailing spaces and '/' in url
	return strings.TrimRight(url, " /"), ""
}
