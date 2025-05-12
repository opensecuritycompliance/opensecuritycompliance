package semgrepconnector

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
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

type SemgrepConnector struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"appPort"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
	LinkedApplications     *LinkedApplications     `json:"linkedApplications" yaml:"linkedApplications"`
}

func (thisObj *SemgrepConnector) Validate() (bool, error) {
	_, err := thisObj.GetDeployments()
	if err != nil {
		return false, err
	}
	return true, nil
}

func (thisObj *SemgrepConnector) GetHeaders() map[string]string {
	return map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", thisObj.UserDefinedCredentials.AccessToken.AccessToken),
		"Content-Type":  "application/json",
	}
}

func (thisObj *SemgrepConnector) GetDeployments() (map[string]interface{}, error) {
	url := "https://semgrep.dev/api/v1/deployments"
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("request creation error: %v", err)
	}

	for key, value := range thisObj.GetHeaders() {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("Invalid AccessToken.")
		}
		return nil, fmt.Errorf("HTTP error: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body error: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal error: %v", err)
	}

	return result, nil
}

func (accesstoken *AccessToken) ValidateAttributes() string {
	var emptyAttributes []string
	errorResultStr := ""
	if accesstoken.AccessToken == "" {
		emptyAttributes = append(emptyAttributes, "AccessToken")
	}
	if len(emptyAttributes) > 0 {
		errorResultStr = fmt.Sprintf("Invalid Credentials: %s is empty", strings.Join(emptyAttributes, ", "))
	}
	return errorResultStr
}
