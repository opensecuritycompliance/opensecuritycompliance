package gcpconnector

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"

	cowlibutils "cowlibrary/utils"
	"cowlibrary/vo"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

const (
	SERVICE_ACCOUNT_FILE_NAME = "ServiceAccountCredential.json"
)

type GoogleWorkSpace struct {
	UserEmail             string   `json:"userEmail" yaml:"UserEmail"`
	ServiceAccountKeyFile vo.Bytes `json:"serviceAccountKeyFile" yaml:"ServiceAccountKeyFile"`
}

type UserDefinedCredentials struct {
	GoogleWorkSpace GoogleWorkSpace `json:"googleWorkSpace" yaml:"GoogleWorkSpace"`
}

type LinkedApplications struct {
}

type GCPConnector struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"appPort"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
	LinkedApplications     *LinkedApplications     `json:"linkedApplications" yaml:"linkedApplications"`
}

func (thisObj *GoogleWorkSpace) ValidateAttributes() string {
	var emptyAttributes []string
	errorResultStr := ""
	if cowlibutils.IsEmpty(thisObj.UserEmail) {
		emptyAttributes = append(emptyAttributes, "UserEmail")
	}
	if cowlibutils.IsEmpty(string(thisObj.ServiceAccountKeyFile)) {
		emptyAttributes = append(emptyAttributes, "ServiceAccountKeyFile")
	}
	if len(emptyAttributes) > 0 {
		errorResultStr = fmt.Sprintf("Invalid Credentials: %s", strings.Join(emptyAttributes, ", ")+" is empty")
	}
	return errorResultStr
}

func (thisObj *GCPConnector) Validate() (bool, error) {

	gws := &thisObj.UserDefinedCredentials.GoogleWorkSpace
	if errMsg := gws.ValidateAttributes(); cowlibutils.IsNotEmpty(errMsg) {
		return false, fmt.Errorf(errMsg)
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(gws.UserEmail) {
		return false, fmt.Errorf("Invalid 'UserEmail'")
	}

	service, err := gws.CreateAdminService(admin.AdminDirectoryDomainReadonlyScope)
	if err != nil {
		return false, fmt.Errorf("Failed to create application: %v", err)
	}
	/*
	  Here validating app by fetching domain details.
	  hence adding the scope AdminDirectoryDomainReadonlyScope - "https://www.googleapis.com/auth/admin.directory.domain.readonly"
	  in Domain-wide Delegation will be mandatory for validating application

	  "my_customer" -  alias to represent account's `customerId`
	*/
	domain := gws.GetDomainName()
	if domain == "" {
		return false, fmt.Errorf("Invalid 'UserEmail': missing domain")
	}

	_, err = service.Domains.Get("my_customer", domain).Do()
	if err != nil {
		return false, fmt.Errorf("Invalid 'UserEmail' or 'ServiceAccountKeyFile': %v", err)
	}

	return true, nil
}

func (thisObj *GoogleWorkSpace) CreateAdminService(scope string) (*admin.Service, error) {
	tokenSource, context, err := thisObj.GetServiceConfigDetails(scope)
	if err != nil {
		return nil, fmt.Errorf("Failed to create service : %v", err)
	}

	// Create a admin service with the token source
	service, err := admin.NewService(context, option.WithTokenSource(tokenSource))
	if err != nil {
		return nil, fmt.Errorf("Failed to create Admin SDK service: %v", err)
	}
	return service, nil
}

func (thisObj *GoogleWorkSpace) GetDomainName() string {
	parts := strings.Split(thisObj.UserEmail, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

func (thisObj *GoogleWorkSpace) GetServiceConfigDetails(scope string) (oauth2.TokenSource, context.Context, error) {
	ctx := context.Background()
	credentials, err := google.JWTConfigFromJSON(thisObj.ServiceAccountKeyFile, scope)
	if err != nil {
		return nil, nil, fmt.Errorf("Invalid service account key file: %v", err)
	}

	// Set the subject (user email) for domain-wide delegation
	credentials.Subject = thisObj.UserEmail
	tokenSource := credentials.TokenSource(ctx)

	return tokenSource, ctx, nil
}

func (thisObj *GoogleWorkSpace) CreateConfig(scope string) (*jwt.Config, error) {

	serviceAccountJSONKeyDecoded, err := thisObj.DecodeServiceAccountJson(string(thisObj.ServiceAccountKeyFile))
	if err != nil {
		return nil, err
	}

	err = os.WriteFile(SERVICE_ACCOUNT_FILE_NAME, serviceAccountJSONKeyDecoded, 0644)
	if err != nil {
		return nil, fmt.Errorf("Failed to create a service account credential file for internal handling :: %v", err)
	}
	defer os.Remove(SERVICE_ACCOUNT_FILE_NAME)

	jsonCredentials, err := os.ReadFile(SERVICE_ACCOUNT_FILE_NAME)
	if err != nil {
		return nil, fmt.Errorf("Failed to read service credential account file ::  %v", err)
	}

	// Create a JWT config from JSON credentials
	config, err := google.JWTConfigFromJSON(jsonCredentials, scope)
	if err != nil {
		return nil, fmt.Errorf("Failed to create JWT config ::  %v", err)
	}

	return config, nil

}

func (thisObj *GoogleWorkSpace) DecodeServiceAccountJson(serviceAccountJSONKeyEncoded string) ([]byte, error) {

	serviceAccountJSONKeyDecoded, err := base64.StdEncoding.DecodeString(serviceAccountJSONKeyEncoded)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode service account credential :: %v", err)
	}
	return serviceAccountJSONKeyDecoded, nil
}
