package azureappconnector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	gourl "net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription"
	"github.com/go-resty/resty/v2"
)

const (
	MANAGEMENT_API_SCOPE    = "https://management.azure.com/.default"
	GRAPH_API_SCOPE         = "https://graph.microsoft.com/.default"
	LOG_ANALYTICS_API_SCOPE = "https://api.loganalytics.io/.default"
)

type Azure struct {
	ClientSecret   string `json:"clientSecret" yaml:"clientSecret"`
	TenantID       string `json:"tenantID" yaml:"tenantID"`
	SubscriptionID string `json:"subscriptionID" yaml:"subscriptionID"`
	ClientID       string `json:"clientID" yaml:"clientID"`
}

type UserDefinedCredentials struct {
	Azure Azure `json:"azure" yaml:"Azure"`
}

type AzureAppConnector struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"port"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
}

func (thisObj *AzureAppConnector) Validate() (bool, error) {

	err := thisObj.CheckAzureCredentials()
	if err != nil {
		return false, err
	}
	return true, nil

}

func (thisObj *AzureAppConnector) CheckAzureCredentials() error {
	creds := []string{}
	if thisObj.UserDefinedCredentials == nil {
		return fmt.Errorf("UserInputs is empty")
	}
	if thisObj.UserDefinedCredentials.Azure.ClientID == "" {
		creds = append(creds, "ClientID is empty")
	}
	if thisObj.UserDefinedCredentials.Azure.ClientSecret == "" {
		creds = append(creds, "ClientSecret is empty")
	}
	if thisObj.UserDefinedCredentials.Azure.TenantID == "" {
		creds = append(creds, "TenantID is empty")
	}
	if thisObj.UserDefinedCredentials.Azure.SubscriptionID == "" {
		creds = append(creds, "SubscriptionID is empty")
	}

	if len(creds) > 0 {
		return fmt.Errorf("%s", strings.Join(creds, ", "))
	}
	err := thisObj.ValidateAzureCredentials()
	return err
}

func (thisObj *AzureAppConnector) ValidateAzureCredentials() error {

	cred, err := azidentity.NewClientSecretCredential(
		thisObj.UserDefinedCredentials.Azure.TenantID,
		thisObj.UserDefinedCredentials.Azure.ClientID,
		thisObj.UserDefinedCredentials.Azure.ClientSecret,
		nil,
	)
	if err != nil {
		return fmt.Errorf("Error creating credential: %v\n", err)
	}

	client, err := armsubscription.NewSubscriptionsClient(cred, nil)
	if err != nil {
		return fmt.Errorf("Error creating client: %v\n", err)
	}

	_, err = client.Get(context.TODO(), thisObj.UserDefinedCredentials.Azure.SubscriptionID, nil)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "unauthorized_client") {
			return fmt.Errorf("Error in creating access token. Invalid ClientID")
		} else if strings.Contains(errMsg, "invalid_client") {
			return fmt.Errorf("Error in creating access token. Invalid ClientSecret")
		} else if strings.Contains(errMsg, "invalid_tenant") {
			return fmt.Errorf("Error in creating access token. Invalid TenantID")
		} else if strings.Contains(errMsg, "InvalidSubscriptionId") {
			return fmt.Errorf("Invalid SubscriptionID")
		} else {
			return fmt.Errorf("Error getting subscription: %v\n", err)
		}
	}

	// If we get here, the credentials are valid
	return nil
}

func (thisObj *AzureAppConnector) GetAzureCredentials() (clientId, clientSecret, tenantID, subscriptionID string, err error) {
	err = thisObj.CheckAzureCredentials()
	if err != nil {
		return "", "", "", "", err
	}
	azure := thisObj.UserDefinedCredentials.Azure
	clientId = azure.ClientID
	clientSecret = azure.ClientSecret
	tenantID = azure.TenantID
	subscriptionID = azure.SubscriptionID

	return clientId, clientSecret, tenantID, subscriptionID, nil
}

func (thisObj *AzureAppConnector) GetAzureAPIResponse(azureApiVO AzureApiVO) ([]byte, error) {
	err := thisObj.CheckAzureCredentials()
	if err != nil {
		return nil, err
	}
	var req *http.Request
	if azureApiVO.Method == http.MethodPost {
		jsonStr, err := json.Marshal(azureApiVO.Body)
		if err != nil {
			return nil, err
		}
		req, err = http.NewRequest(azureApiVO.Method, azureApiVO.Url, bytes.NewBuffer(jsonStr))
		if err != nil {
			return nil, err
		}
	} else {
		req, err = http.NewRequest(azureApiVO.Method, azureApiVO.Url, nil)
		if err != nil {
			return nil, err
		}
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", azureApiVO.AccessToken)
	res, err := http.DefaultClient.Do(req)
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
	} else {
		errNew := errors.New(string(resBody))
		return nil, errNew
	}
}
func (thisObj *AzureAppConnector) GetAzureAPIResponseUsingResty(url, scope string) ([]byte, error) {

	resourceDetails := make([]interface{}, 0)
	_, _, _, subscriptionID, err := thisObj.GetAzureCredentials()
	if err != nil {
		return nil, err
	}

	url = strings.Replace(url, "<<subscription_id>>", subscriptionID, 1)

	accessToken, err := thisObj.GetAzureAccessTokenUsingResty(MANAGEMENT_API_SCOPE)
	if err != nil {
		return nil, err
	}
	client := resty.New()

	maxRetryRequest := 3
	retryRequest := 0

	for {
		var azureResp AzureAPIResponse
		resp, err := client.R().SetHeader("Authorization", fmt.Sprintf("Bearer %v", accessToken)).SetResult(&azureResp).Get(url)
		if err != nil {
			return nil, fmt.Errorf("Failed to make Azure API request: %v", err)
		}

		if resp.StatusCode() != http.StatusOK {
			retryRequest += 1
			if retryRequest < maxRetryRequest {
				continue
			}
		}

		if resp.IsError() {
			return nil, fmt.Errorf("Azure API request failed with status code: %d", resp.StatusCode())
		}

		if len(azureResp.Value) != 0 {
			resourceDetails = append(resourceDetails, azureResp.Value...)
		}

		if azureResp.NextLink == "" && azureResp.ODataNextLink == "" {
			break
		}

		url = azureResp.NextLink
		if url == "" {
			url = azureResp.ODataNextLink
		}
	}

	resourceDetailsBytes, err := json.Marshal(resourceDetails)
	if err != nil {
		return nil, fmt.Errorf("Error while Marshalling response body: %d", err)
	}

	return resourceDetailsBytes, nil
}

func (thisObj *AzureAppConnector) ListManagedClusters() ([]byte, error) {

	clusterURL := "https://management.azure.com/subscriptions/<<subscription_id>>/providers/Microsoft.ContainerService/managedClusters?api-version=2021-03-01"
	clusterListBytes, err := thisObj.GetAzureAPIResponseUsingResty(clusterURL, MANAGEMENT_API_SCOPE)
	if err != nil {
		return nil, fmt.Errorf("Error occured while listing clusters : %v", err)
	}

	return clusterListBytes, nil
}

func (thisObj *AzureAppConnector) GetAzureAccessToken(azureApiVO AzureApiVO) (string, error) {

	var accessToken string
	url := fmt.Sprintf("https://login.microsoftonline.com/%v/oauth2/token", azureApiVO.TenantID)
	form := gourl.Values{}
	form.Add("grant_type", "client_credentials")
	form.Add("client_id", azureApiVO.ClientID)
	form.Add("client_secret", azureApiVO.ClientSecret)
	form.Add("resource", azureApiVO.Scope)

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		var credential AzureClientCredential
		err = json.Unmarshal(body, &credential)
		if err != nil {
			return "", err
		}
		accessToken = "Bearer " + credential.AccessToken
		return accessToken, nil
	} else {
		errNew := errors.New(string(body))
		return "", errNew
	}

}

func (thisObj *AzureAppConnector) GetDefenderAssessments() (AssessmentResponse, error) {

	var DefenderAssessmentResponse AssessmentResponse

	clientID, clientSecret, tenantID, subscriptionID, err := thisObj.GetAzureCredentials()
	if err != nil {
		return DefenderAssessmentResponse, err
	}

	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Security/assessments?api-version=2020-01-01", subscriptionID)
	method := http.MethodGet
	scope := "https://management.azure.com"
	azureApiVO := AzureApiVO{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TenantID:     tenantID,
		Scope:        scope,
		Url:          url,
		Method:       method,
	}
	accessToken, err := thisObj.GetAzureAccessToken(azureApiVO)
	if err != nil {
		return DefenderAssessmentResponse, err
	}
	azureApiVO.AccessToken = accessToken
	for {
		var assessmentRes AssessmentResponse
		response, err := thisObj.GetAzureAPIResponse(azureApiVO)
		if err != nil {
			if strings.Contains(err.Error(), "AuthenticationFailed") {
				accessTokenTemp, err := thisObj.GetAzureAccessToken(azureApiVO)
				if err != nil {
					return DefenderAssessmentResponse, err
				}
				azureApiVO.AccessToken = accessTokenTemp

				response, err = thisObj.GetAzureAPIResponse(azureApiVO)
				if err != nil {
					return assessmentRes, err
				}

			} else {
				return assessmentRes, err

			}
		}
		err = json.Unmarshal(response, &assessmentRes)
		if err != nil {
			return assessmentRes, err
		}

		DefenderAssessmentResponse.Value = append(DefenderAssessmentResponse.Value, assessmentRes.Value...)
		if assessmentRes.NextLink != "" {
			azureApiVO.Url = assessmentRes.NextLink
		} else {
			break
		}

	}

	return DefenderAssessmentResponse, nil
}

func (thisObj *AzureAppConnector) GetAzureAccessTokenUsingResty(scope string) (string, error) {

	url := fmt.Sprintf("https://login.microsoftonline.com/%v/oauth2/v2.0/token", thisObj.UserDefinedCredentials.Azure.TenantID)
	formData := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     thisObj.UserDefinedCredentials.Azure.ClientID,
		"client_secret": thisObj.UserDefinedCredentials.Azure.ClientSecret,
		"scope":         scope,
	}
	headers := make(map[string]string)
	headers["Content-Type"] = "application/x-www-form-urlencoded"
	var credential AzureClientCredentialV1
	resp, err := resty.New().R().SetFormData(formData).SetResult(&credential).Post(url)
	if err != nil {
		return "", err
	} else if resp.StatusCode() != http.StatusOK {
		return "", fmt.Errorf("fetching access token for azure account is not success. Status code :: %v", resp.StatusCode())
	} else if credential.AccessToken == "" {
		return "", fmt.Errorf("invalid access token")
	} else {
		return credential.AccessToken, nil
	}

}

func (thisObj *AzureAppConnector) GetResourceUrl(resourceId string) (string, error) {
	url := "https://portal.azure.com/#@<<domain_name>>/resource<<resource_id>>/overview"
	domainName, err := thisObj.GetDomainName(resourceId)
	if err != nil {
		return "", err
	}
	modifiedUrl := strings.Replace(strings.Replace(url, "<<domain_name>>", domainName, 1), "<<resource_id>>", resourceId, 1)
	return modifiedUrl, nil
}

func (thisObj *AzureAppConnector) GetDomainName(resourceId string) (string, error) {
	accessToken, err := thisObj.GetAzureAccessTokenUsingResty(GRAPH_API_SCOPE)
	if err != nil {
		return "", err
	}
	domainDetails, err := thisObj.GetAzureAPIResponse(AzureApiVO{
		AccessToken: fmt.Sprintf("Bearer %v", accessToken),
		Url:         "https://graph.microsoft.com/v1.0/domains",
	})
	if err != nil {
		return "", err
	}
	var domainData DomainDetailsVO
	err = json.Unmarshal(domainDetails, &domainData)
	if err != nil {
		return "", err
	}
	for _, domain := range domainData.Value {
		if domain.IsDefault {
			return domain.ID, nil
		}
	}
	return "", fmt.Errorf("unable to fetch the default domain name for the azure account")
}

type AzureClientCredential struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    string `json:"expires_in"`
	ExtExpiresIn string `json:"ext_expires_in"`
	ExpiresOn    string `json:"expires_on"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	AccessToken  string `json:"access_token"`
}

type AzureClientCredentialV1 struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	ExtExpiresIn int    `json:"ext_expires_in"`
	AccessToken  string `json:"access_token"`
}

type AzureApiVO struct {
	ClientID     string      `json:"client_id"`
	ClientSecret string      `json:"client_secret"`
	TenantID     string      `json:"tenant_id"`
	Scope        string      `json:"scope"`
	Url          string      `json:"url"`
	Method       string      `json:"method"`
	Body         interface{} `json:"body"`
	AccessToken  string      `json:"access_token"`
}

type AssessmentResponse struct {
	NextLink string `json:"nextLink"`
	Value    []struct {
		Type       string `json:"Type"`
		ID         string `json:"ID"`
		Name       string `json:"Name"`
		Properties struct {
			ResourceDetails struct {
				Source string `json:"Source"`
				ID     string `json:"ID"`
			} `json:"ResourceDetails"`
			DisplayName string `json:"DisplayName"`
			Status      struct {
				Code        string `json:"Code"`
				Cause       string `json:"Cause"`
				Description string `json:"Description"`
			} `json:"Status"`
			AdditionalData map[string]interface{} `json:"AdditionalData"`
		} `json:"Properties"`
	} `json:"value"`
}

type DomainDetailsVO struct {
	OdataContext string `json:"@odata.context"`
	Value        []struct {
		AuthenticationType               string      `json:"authenticationType"`
		AvailabilityStatus               interface{} `json:"availabilityStatus"`
		ID                               string      `json:"id"`
		IsAdminManaged                   bool        `json:"isAdminManaged"`
		IsDefault                        bool        `json:"isDefault"`
		IsInitial                        bool        `json:"isInitial"`
		IsRoot                           bool        `json:"isRoot"`
		IsVerified                       bool        `json:"isVerified"`
		SupportedServices                []string    `json:"supportedServices"`
		PasswordValidityPeriodInDays     int         `json:"passwordValidityPeriodInDays"`
		PasswordNotificationWindowInDays int         `json:"passwordNotificationWindowInDays"`
		State                            interface{} `json:"state"`
	} `json:"value"`
}

type AzureAPIResponse struct {
	Value         []interface{} `json:"value"`
	NextLink      string        `json:"nextLink"`
	ODataNextLink string        `json:"@odata.nextLink"`
}
