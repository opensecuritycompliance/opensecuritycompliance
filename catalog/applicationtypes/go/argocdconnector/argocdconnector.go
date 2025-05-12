package argocdconnector

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type BasicAuthentication struct {
	UserName string `json:"userName" yaml:"UserName"`
	Password string `json:"password" yaml:"Password"`
}

type UserDefinedCredentials struct {
	BasicAuthentication BasicAuthentication `json:"basicAuthentication" yaml:"BasicAuthentication"`
}

type LinkedApplications struct {
}

type ArgoCDConnector struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"appPort"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
	LinkedApplications     *LinkedApplications     `json:"linkedApplications" yaml:"linkedApplications"`
}

func (thisObj *ArgoCDConnector) Validate() (bool, error) {
	basicAuth := thisObj.UserDefinedCredentials.BasicAuthentication
	token, err := thisObj.getAPIToken(basicAuth.UserName, basicAuth.Password)
	if err != nil {
		return false, err
	}
	isEnabled, err := thisObj.verifyAccount(token)
	if err != nil {
		return false, err
	}
	return isEnabled, nil
}

func (basicauthentication *BasicAuthentication) ValidateAttributes() string {
	var emptyAttributes []string
	errorResultStr := ""
	if basicauthentication.UserName == "" {
		emptyAttributes = append(emptyAttributes, "UserName")
	}
	if basicauthentication.Password == "" {
		emptyAttributes = append(emptyAttributes, "Password")
	}
	if len(emptyAttributes) > 0 {
		errorResultStr = fmt.Sprintf("Invalid Credentials: %s", strings.Join(emptyAttributes, ", ")+" is empty")
	}
	return errorResultStr
}

// getAPIToken gets the API token using the provided username and password
func (thisObj *ArgoCDConnector) getAPIToken(username, password string) (string, error) {
	url := fmt.Sprintf("%s/api/v1/session", thisObj.AppURL)
	method := "POST"
	payload := strings.NewReader(fmt.Sprintf(`{
		"username": "%s",
		"password": "%s"
	}`, username, password))

	// Create a custom HTTP client with TLS config to skip SSL verification
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Disable SSL certificate verification
		},
	}

	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", handleRequestError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", handleHTTPError(resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result map[string]string
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", err
	}

	token, exists := result["token"]
	if !exists {
		return "", errors.New("token not found in the response")
	}

	return token, nil
}

// verifyAccount checks if the user account is enabled
func (thisObj *ArgoCDConnector) verifyAccount(token string) (bool, error) {
	basicAuth := thisObj.UserDefinedCredentials.BasicAuthentication
	url := fmt.Sprintf("%s/api/v1/account/%s", thisObj.AppURL, basicAuth.UserName)
	method := "GET"

	// Create a custom HTTP client with TLS config to skip SSL verification
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Disable SSL certificate verification
		},
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return false, handleRequestError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, handleHTTPError(resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var accountData map[string]interface{}
	err = json.Unmarshal(body, &accountData)
	if err != nil {
		return false, err
	}

	enabled, exists := accountData["enabled"].(bool)
	if !exists || !enabled {
		return false, nil
	}

	return true, nil
}

// handleRequestError maps request errors to specific error messages
func handleRequestError(err error) error {
	urlErr, ok := err.(*url.Error)
	if ok && urlErr.Timeout() {
		return errors.New("Timeout error: Invalid URL.")
	}
	return errors.New("Connection error: Invalid URL.")
}

// handleHTTPError maps HTTP status codes to error messages
func handleHTTPError(statusCode int) error {
	switch statusCode {
	case http.StatusUnauthorized:
		return errors.New("Error 401: unauthorized. Invalid username and/or password.")
	case http.StatusForbidden:
		return errors.New("Error 403: forbidden. Invalid username and/or password.")
	case http.StatusNotFound:
		return errors.New("Error 404: Invalid username and/or password.")
	default:
		return fmt.Errorf("http error: status code %d", statusCode)
	}
}
