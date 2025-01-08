package snykappconnector

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type SnykCredential struct {
	ApiKey string `json:"apiKey" yaml:"ApiKey"`
}

type UserDefinedCredentials struct {
	SnykCredential SnykCredential `json:"snykCredential" yaml:"SnykCredential"`
}

type LinkedApplications struct {
}

type SnykAppConnector struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"appPort"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
	LinkedApplications     *LinkedApplications     `json:"linkedApplications" yaml:"linkedApplications"`
}

type SelfResponse struct {
	Data struct {
		Attributes struct {
			DefaultOrgContext string `json:"default_org_context"`
			Username          string `json:"username"`
		} `json:"attributes"`
	} `json:"data"`
}

func (thisObj *SnykAppConnector) Validate() (bool, error) {
	if thisObj.UserDefinedCredentials == nil {
		return false, errors.New("User Inputs is empty")
	}

	if (thisObj.UserDefinedCredentials.SnykCredential == SnykCredential{}) {
		return false, errors.New("Couldn't find SnykCredential in user defined credentials")
	}

	err := thisObj.UserDefinedCredentials.SnykCredential.ValidateAttributes()
	if err != nil {
		return false, err
	}

	orgID, _, err := thisObj.GetSelfDetails()
	if err != nil {
		return false, err
	}

	loginURL := strings.TrimRight(thisObj.AppURL, "/")
	validationURL := fmt.Sprintf("%s/rest/orgs/%s/settings/sast?version=2024-06-10", loginURL, orgID)

	_, newErr := thisObj.GetApiResponseFromSnyk(http.MethodGet, validationURL, nil)
	if newErr != nil {
		if strings.Contains(newErr.Error(), "Unauthorized") ||
			strings.Contains(newErr.Error(), "Access Forbidden") ||
			strings.Contains(newErr.Error(), "Account trial expired") {
			return false, fmt.Errorf("Invalid API Key.")
		} else {
			return false, fmt.Errorf("Invalid URL.")
		}
	}

	return true, nil
}

func (snykcredential *SnykCredential) ValidateAttributes() error {
	var emptyAttributes []string
	if snykcredential.ApiKey == "" {
		emptyAttributes = append(emptyAttributes, "ApiKey")
	}
	if len(emptyAttributes) > 0 {
		return fmt.Errorf("Invalid Credentials: %s is empty", strings.Join(emptyAttributes, ", "))
	}
	return nil
}

// INFO : You can implement your own implementation for the class

func (thisObj *SnykAppConnector) GetApiResponseFromSnyk(method string, url string, body interface{}) ([]byte, error) {

	token := fmt.Sprintf("token %s", thisObj.UserDefinedCredentials.SnykCredential.ApiKey)
	var req *http.Request
	var err error
	client := &http.Client{}
	if method == http.MethodGet {
		req, err = http.NewRequest(method, url, nil)
		if err != nil {
			return nil, err
		}
	} else {

		jsonStr, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload := strings.NewReader(string(jsonStr))
		req, err = http.NewRequest(method, url, payload)
		if err != nil {
			return nil, err
		}

	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", token)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusCreated {
		return resBody, nil
	} else if res.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("Unauthorized")
	} else if res.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("Access Forbidden")
	} else if res.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("URL not found")
	} else {
		return nil, errors.New(string(resBody))
	}
}

// Additional method to get authenticated user details
func (thisObj *SnykAppConnector) GetSelfDetails() (string, string, error) {
	baseURL := thisObj.AppURL
	url := fmt.Sprintf("%s/rest/self", baseURL)

	params := "version=2024-08-22"
	apiKey := thisObj.UserDefinedCredentials.SnykCredential.ApiKey
	headers := http.Header{}
	headers.Add("Authorization", fmt.Sprintf("token %s", apiKey))
	headers.Add("Content-Type", "application/json")

	req, err := http.NewRequest(http.MethodGet, url+"?"+params, nil)
	if err != nil {
		return "", "", err
	}
	req.Header = headers

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("Failed to get user details: %s", resp.Status)
	}

	var responseData SelfResponse
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	if err := json.Unmarshal(body, &responseData); err != nil {
		return "", "", err
	}

	if responseData.Data.Attributes.DefaultOrgContext == "" {
		return "", "", errors.New("default_org_context is missing")
	}
	if responseData.Data.Attributes.Username == "" {
		return "", "", errors.New("username is missing")
	}

	return responseData.Data.Attributes.DefaultOrgContext, responseData.Data.Attributes.Username, nil
}
