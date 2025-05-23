package teamcityconnector

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type AccessToken struct {
	AccessToken string `json:"accessToken" yaml:"AccessToken"`
}

type UserDefinedCredentials struct {
	AccessToken AccessToken `json:"accessToken" yaml:"AccessToken"`
}

type LinkedApplications struct {
}

type TeamCityConnector struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"appPort"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
	LinkedApplications     *LinkedApplications     `json:"linkedApplications" yaml:"linkedApplications"`
}

func (thisObj *TeamCityConnector) Validate() (bool, error) {
	url, errStr := thisObj.getAppURL()
	if errStr != "" {
		return false, errors.New(errStr)
	}

	req, err := http.NewRequest("GET", url+"/app/rest/users", nil)
	if err != nil {
		return false, fmt.Errorf("Error creating request: %w", err)
	}

	if thisObj.UserDefinedCredentials != nil {
		accessToken := thisObj.UserDefinedCredentials.AccessToken.AccessToken
		if accessToken != "" {
			req.Header.Add("Authorization", "Bearer "+accessToken)
		}
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Accept", "application/json")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, errors.New("Invalid URL, please check.")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return false, errors.New("Invalid Access Token, please check.")
	} else if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("An unknown error has occurred, response status code: %v", resp.StatusCode)
	}

	return true, nil
}

func (accesstoken *AccessToken) ValidateAttributes() string {
	var emptyAttributes []string
	errorResultStr := ""
	if accesstoken.AccessToken == "" {
		emptyAttributes = append(emptyAttributes, "AccessToken")
	}
	if len(emptyAttributes) > 0 {
		errorResultStr = fmt.Sprintf("Invalid Credentials: %s", strings.Join(emptyAttributes, ", ")+" is empty")
	}
	return errorResultStr
}

func (thisObj *TeamCityConnector) getAppURL() (string, string) {
	url := thisObj.AppURL
	if url == "" {
		return "", "AppURL is empty"
	}

	// remove trailing spaces and '/' in url
	return strings.TrimRight(url, " /"), ""
}
