package oktaconnector

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/okta/okta-sdk-golang/v2/okta"
)

type APIKey struct {
	APIKey string `json:"aPIKey" yaml:"APIKey"`
}

type UserDefinedCredentials struct {
	APIKey APIKey `json:"aPIKey" yaml:"APIKey"`
}

type OktaConnector struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"port"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
	Client                 *okta.Client
}

func (thisObj *OktaConnector) Validate() (bool, error) {
	err := thisObj.createNewClient()
	if err != nil {
		return false, err
	}

	_, _, err = thisObj.Client.User.GetUser(context.Background(), "me")
	if err != nil {
		return false, thisObj.getOktaErrorMsg(err)
	}

	return true, nil
}

func (thisObj *OktaConnector) createNewClient() error {
	if strings.Contains(thisObj.AppURL, "-admin") {
		return errors.New("your Okta domain should not contain -admin. You can copy your domain from the Okta Developer Console. Follow these instructions to find it: https://developer.okta.com/docs/guides/find-your-domain/overview")
	}

	err := thisObj.UserDefinedCredentials.APIKey.ValidateAttributes()
	if err != "" {
		return errors.New(err)
	}

	if thisObj.Client == nil {
		_, client, err := okta.NewClient(context.Background(), okta.WithOrgUrl(thisObj.AppURL), okta.WithToken(thisObj.UserDefinedCredentials.APIKey.APIKey))
		if err != nil {
			return err
		}
		thisObj.Client = client
	}

	return nil
}

func (thisObj *OktaConnector) getOktaErrorMsg(err error) error {
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			return errors.New("Invalid AppURL")
		} else if oktaErr, ok := err.(*okta.Error); ok {
			if strings.Contains(oktaErr.ErrorSummary, "Invalid token provided") {
				return errors.New("Invalid URL/APIKey. Please check.")
			}
			return errors.New(oktaErr.Error())
		} else {
			return err
		}
	}
	return nil
}

func (apikey *APIKey) ValidateAttributes() string {
	var emptyAttributes []string
	errorResultStr := ""
	if apikey.APIKey == "" {
		emptyAttributes = append(emptyAttributes, "APIKey")
	}
	if len(emptyAttributes) > 0 {
		errorResultStr = fmt.Sprintf("Invalid Credentials: %s", strings.Join(emptyAttributes, ", ")+" is empty")
	}
	return errorResultStr
}

// INFO : You can implement your own implementation for the class
