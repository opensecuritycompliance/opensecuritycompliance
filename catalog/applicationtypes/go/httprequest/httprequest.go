package httprequest

import (
	cowlibutils "cowlibrary/utils"
	"cowlibrary/vo"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/uuid"
)

type APIKey struct {
	ValidationCURL string `json:"validationCURL" yaml:"ValidationCURL"`
	APIKey         string `json:"aPIKey" yaml:"APIKey"`
}
type NoAuth struct {
}
type JWTBearer struct {
	Algorithm      string   `json:"algorithm" yaml:"Algorithm"`
	PrivateKey     vo.Bytes `json:"privateKey" yaml:"PrivateKey"`
	Payload        string   `json:"payload" yaml:"Payload"`
	ValidationCURL string   `json:"validationCURL" yaml:"ValidationCURL"`
}
type AWSSignature struct {
	ValidationCURL string `json:"validationCURL" yaml:"ValidationCURL"`
	AccessKey      string `json:"accessKey" yaml:"AccessKey"`
	SecretKey      string `json:"secretKey" yaml:"SecretKey"`
}
type BearerToken struct {
	ValidationCURL string `json:"validationCURL" yaml:"ValidationCURL"`
	Token          string `json:"token" yaml:"Token"`
}
type BasicAuthentication struct {
	ValidationCURL string `json:"validationCURL" yaml:"ValidationCURL"`
	UserName       string `json:"userName" yaml:"UserName"`
	Password       string `json:"password" yaml:"Password"`
}
type OAuth struct {
	ValidationCURL string `json:"validationCURL" yaml:"ValidationCURL"`
	ClientID       string `json:"clientID" yaml:"ClientID"`
	ClientSecret   string `json:"clientSecret" yaml:"ClientSecret"`
}
type CustomType struct {
	ValidationCURL string   `json:"validationCURL" yaml:"ValidationCURL"`
	CredentialJson vo.Bytes `json:"credentialJson" yaml:"CredentialJson"`
}
type Options struct {
	Region string
}
type UserDefinedCredentials struct {
	APIKey              APIKey              `json:"aPIKey" yaml:"APIKey"`
	NoAuth              *NoAuth             `json:"noAuth" yaml:"NoAuth"`
	JWTBearer           JWTBearer           `json:"jWTBearer" yaml:"JWTBearer"`
	AWSSignature        AWSSignature        `json:"aWSSignature" yaml:"AWSSignature"`
	BearerToken         BearerToken         `json:"bearerToken" yaml:"BearerToken"`
	BasicAuthentication BasicAuthentication `json:"basicAuthentication" yaml:"BasicAuthentication"`
	OAuth               OAuth               `json:"oAuth" yaml:"OAuth"`
	CustomType          CustomType          `json:"customType" yaml:"CustomType"`
}

type LinkedApplications struct {
}

type HttpRequest struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"appPort"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
	LinkedApplications     *LinkedApplications     `json:"linkedApplications" yaml:"linkedApplications"`
}

func (thisObj *HttpRequest) Validate() (bool, error) {

	if thisObj.UserDefinedCredentials == nil || thisObj.UserDefinedCredentials.NoAuth != nil {
		return true, nil
	}

	credsAwsRole := thisObj.UserDefinedCredentials.AWSSignature
	if !(cowlibutils.IsEmpty(credsAwsRole.AccessKey) || cowlibutils.IsEmpty(credsAwsRole.SecretKey)) {
		return thisObj.ValidateAWSSignature()
	}

	credsJWTBearer := thisObj.UserDefinedCredentials.JWTBearer
	if !(cowlibutils.IsEmpty(credsJWTBearer.Algorithm) || cowlibutils.IsEmpty(credsJWTBearer.Payload)) {
		isvalid, err := thisObj.ValidateCredentialsType("JWTBearer", credsJWTBearer.ValidationCURL)
		if isvalid {
			return thisObj.ValidateJWTBearer()
		}
		return false, errors.New(err)
	}

	credsBasicAuth := thisObj.UserDefinedCredentials.BasicAuthentication
	if !(cowlibutils.IsEmpty(credsBasicAuth.UserName) || cowlibutils.IsEmpty(credsBasicAuth.Password)) {
		isvalid, err := thisObj.ValidateCredentialsType("BasicAuthentication", credsBasicAuth.ValidationCURL)
		if isvalid {
			return thisObj.ValidateBasicAuth()
		}
		return false, errors.New(err)
	}

	apiKeyToken := thisObj.UserDefinedCredentials.APIKey
	if !(cowlibutils.IsEmpty(apiKeyToken.APIKey)) {
		isvalid, err := thisObj.ValidateCredentialsType("APIKey", apiKeyToken.ValidationCURL)
		if isvalid {
			return thisObj.ValidateAPIKey()
		}
		return false, errors.New(err)
	}

	credsBearerToken := thisObj.UserDefinedCredentials.BearerToken
	if !(cowlibutils.IsEmpty(credsBearerToken.Token)) {
		isvalid, err := thisObj.ValidateCredentialsType("BearerToken", credsBearerToken.ValidationCURL)
		if isvalid {
			return thisObj.ValidateBearerToken()
		}
		return false, errors.New(err)
	}

	credsCustomType := thisObj.UserDefinedCredentials.CustomType
	if credsCustomType.ValidationCURL != "" {
		return thisObj.ValidateCustomType()
	}

	credsOAuth := thisObj.UserDefinedCredentials.OAuth
	if !(cowlibutils.IsEmpty(credsOAuth.ClientID) || cowlibutils.IsEmpty(credsOAuth.ClientSecret)) {
		isvalid, err := thisObj.ValidateCredentialsType("OAuth", credsOAuth.ValidationCURL)
		if isvalid {
			return thisObj.ValidateOAuth()
		}
		return false, errors.New(err)
	}
	return false, errors.New("invalid Credential Type")
}
func (basicauthentication *BasicAuthentication) ValidateAttributes() string {
	var emptyAttributes []string
	errorResultStr := ""
	if basicauthentication.ValidationCURL == "" {
		emptyAttributes = append(emptyAttributes, "ValidationCURL")
	}
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

func (oauth *OAuth) ValidateAttributes() string {
	var emptyAttributes []string
	errorResultStr := ""
	if oauth.ValidationCURL == "" {
		emptyAttributes = append(emptyAttributes, "ValidationCURL")
	}
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

func (customtype *CustomType) ValidateAttributes() string {
	var emptyAttributes []string
	errorResultStr := ""
	if customtype.ValidationCURL == "" {
		emptyAttributes = append(emptyAttributes, "ValidationCURL")
	}
	if len(emptyAttributes) > 0 {
		errorResultStr = fmt.Sprintf("Invalid Credentials: %s", strings.Join(emptyAttributes, ", ")+" is empty")
	}
	return errorResultStr
}

func (apikey *APIKey) ValidateAttributes() string {
	var emptyAttributes []string
	errorResultStr := ""
	if apikey.ValidationCURL == "" {
		emptyAttributes = append(emptyAttributes, "ValidationCURL")
	}
	if apikey.APIKey == "" {
		emptyAttributes = append(emptyAttributes, "APIKey")
	}
	if len(emptyAttributes) > 0 {
		errorResultStr = fmt.Sprintf("Invalid Credentials: %s", strings.Join(emptyAttributes, ", ")+" is empty")
	}
	return errorResultStr
}

func (noauth *NoAuth) ValidateAttributes() string {
	var emptyAttributes []string
	errorResultStr := ""
	if len(emptyAttributes) > 0 {
		errorResultStr = fmt.Sprintf("Invalid Credentials: %s", strings.Join(emptyAttributes, ", ")+" is empty")
	}
	return errorResultStr
}

func (awssignature *AWSSignature) ValidateAttributes() string {
	var emptyAttributes []string
	errorResultStr := ""
	if awssignature.AccessKey == "" {
		emptyAttributes = append(emptyAttributes, "AccessKey")
	}
	if awssignature.SecretKey == "" {
		emptyAttributes = append(emptyAttributes, "SecretKey")
	}
	if len(emptyAttributes) > 0 {
		errorResultStr = fmt.Sprintf("Invalid Credentials: %s", strings.Join(emptyAttributes, ", ")+" is empty")
	}
	return errorResultStr
}

func (bearertoken *BearerToken) ValidateAttributes() string {
	var emptyAttributes []string
	errorResultStr := ""
	if bearertoken.ValidationCURL == "" {
		emptyAttributes = append(emptyAttributes, "ValidationCURL")
	}
	if bearertoken.Token == "" {
		emptyAttributes = append(emptyAttributes, "Token")
	}
	if len(emptyAttributes) > 0 {
		errorResultStr = fmt.Sprintf("Invalid Credentials: %s", strings.Join(emptyAttributes, ", ")+" is empty")
	}
	return errorResultStr
}

func (thisObj *HttpRequest) CreateAWSSessionWithAccessKey(options Options) (*session.Session, error) {
	iamCreds := thisObj.UserDefinedCredentials.AWSSignature
	config := aws.Config{
		Region:      aws.String(options.Region),
		Credentials: credentials.NewStaticCredentials(iamCreds.AccessKey, iamCreds.SecretKey, ""),
	}
	sess, err := session.NewSession(&config)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return nil, errors.New(aerr.Message())
		}
		return nil, err
	}
	return sess, nil
}

func (thisObj *HttpRequest) ValidateAWSSignature() (bool, error) {
	sess, err := thisObj.CreateAWSSessionWithAccessKey(Options{})
	if err != nil {
		return false, err
	}
	svc := iam.New(sess)
	_, err = svc.GetAccountAuthorizationDetails(&iam.GetAccountAuthorizationDetailsInput{})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == "InvalidClientTokenId" {
				return false, errors.New("Invalid AccessKey")
			} else if aerr.Code() == "SignatureDoesNotMatch" {
				return false, errors.New("Invalid SecretKey")
			} else {
				return false, errors.New(aerr.Message())
			}
		}
		return false, err
	}
	return true, nil
}

func (thisObj *HttpRequest) ValidateBasicAuth() (bool, error) {

	validationCURL := thisObj.UserDefinedCredentials.BasicAuthentication.ValidationCURL
	basicAuthMap, err := thisObj.StructToMap(thisObj.UserDefinedCredentials.BasicAuthentication)
	if err != nil {
		return false, errors.New("Error while converting struct to map.")
	}
	parsedCurl, err := thisObj.ReplacePlaceholder(validationCURL, "BasicAuthentication", basicAuthMap)
	if err != nil {
		return false, errors.New("Error while processing place holders.")
	}

	if strings.Contains(parsedCurl, "<<BasicAuthentication>>") {
		auth := thisObj.GenerateBasicAuth()
		parsedCurl = strings.ReplaceAll(parsedCurl, "<<BasicAuthentication>>", auth)
	}

	return thisObj.ValidateCurl(parsedCurl)
}

func (thisObj *HttpRequest) ValidateJWTBearer() (bool, error) {

	validationCURL := thisObj.UserDefinedCredentials.JWTBearer.ValidationCURL

	algorithm := thisObj.UserDefinedCredentials.JWTBearer.Algorithm
	privateKey := string(thisObj.UserDefinedCredentials.JWTBearer.PrivateKey)

	payload_string := thisObj.UserDefinedCredentials.JWTBearer.Payload
	payload_string, err := thisObj.ReplaceFunctionPlaceholders(payload_string)
	if err != nil {
		return false, err
	}

	var payloadJson map[string]interface{}
	err = json.Unmarshal([]byte(payload_string), &payloadJson)
	if err != nil {
		return false, fmt.Errorf("error decoding 'CredentialJson' data: %w", err)
	}

	token, err := thisObj.GenerateJWToken(algorithm, privateKey, payloadJson)
	if err != nil {
		return false, err
	}
	validationCURL = strings.ReplaceAll(validationCURL, "<<JWTBearer>>", token)

	return thisObj.ValidateCurl(validationCURL)
}

func (thisObj *HttpRequest) ValidateAPIKey() (bool, error) {

	validationCURL := thisObj.UserDefinedCredentials.APIKey.ValidationCURL
	apiKeyMap, err := thisObj.StructToMap(thisObj.UserDefinedCredentials.APIKey)
	if err != nil {
		return false, errors.New("Error while converting struct to map.")
	}
	parsedCurl, err := thisObj.ReplacePlaceholder(validationCURL, "APIKey", apiKeyMap)
	if err != nil {
		return false, errors.New("Error while processing place holders.")
	}

	if strings.Contains(parsedCurl, "<<APIKey>>") {
		auth := thisObj.GenerateAPIKey()
		parsedCurl = strings.ReplaceAll(parsedCurl, "<<APIKey>>", auth)
	}

	return thisObj.ValidateCurl(parsedCurl)
}

func (thisObj *HttpRequest) ValidateBearerToken() (bool, error) {

	validationCURL := thisObj.UserDefinedCredentials.BearerToken.ValidationCURL
	bearerTokenMap, err := thisObj.StructToMap(thisObj.UserDefinedCredentials.BearerToken)
	if err != nil {
		return false, errors.New("Error while converting struct to map.")
	}
	parsedCurl, err := thisObj.ReplacePlaceholder(validationCURL, "BearerToken", bearerTokenMap)
	if err != nil {
		return false, errors.New("Error while processing place holders.")
	}

	if strings.Contains(parsedCurl, "<<BearerToken>>") {
		auth := thisObj.GenerateBearerToken()
		parsedCurl = strings.ReplaceAll(parsedCurl, "<<BearerToken>>", auth)
	}

	return thisObj.ValidateCurl(parsedCurl)
}

func (thisObj *HttpRequest) ValidateCustomType() (bool, error) {

	validationCURL := thisObj.UserDefinedCredentials.CustomType.ValidationCURL
	credentialsJson := make(map[string]interface{})
	credJsonBytes := thisObj.UserDefinedCredentials.CustomType.CredentialJson
	if len(thisObj.UserDefinedCredentials.CustomType.CredentialJson) > 0 {
		err := json.Unmarshal(credJsonBytes, &credentialsJson)
		if err != nil {
			return false, fmt.Errorf("error decoding 'CredentialJson' data: %w", err)
		}
	}

	parsedCurl, err := thisObj.ReplacePlaceholder(validationCURL, "CustomType", credentialsJson)
	if err != nil {
		return false, errors.New("error while processing placeholders")
	}

	isValid, err := thisObj.ValidateCurl(parsedCurl)
	if err != nil {
		return false, err
	}

	return isValid, nil
}

func (thisObj *HttpRequest) ValidateOAuth() (bool, error) {

	validationCURL := thisObj.UserDefinedCredentials.OAuth.ValidationCURL
	oAuthMap, err := thisObj.StructToMap(thisObj.UserDefinedCredentials.OAuth)
	if err != nil {
		return false, errors.New("Error while converting struct to map.")
	}
	parsedCurl, err := thisObj.ReplacePlaceholder(validationCURL, "OAuth", oAuthMap)
	if err != nil {
		return false, errors.New("Error while processing place holders.")
	}

	return thisObj.ValidateCurl(parsedCurl)
}

func (thisObj *HttpRequest) GenerateAPIKey() string {

	apiKeyCred := thisObj.UserDefinedCredentials.APIKey
	return fmt.Sprintf("%v", apiKeyCred.APIKey)
}

func (thisObj *HttpRequest) GenerateBearerToken() string {

	token := thisObj.UserDefinedCredentials.BearerToken.Token
	return fmt.Sprintf("Bearer %s", token)
}

func (thisObj *HttpRequest) GenerateBasicAuth() string {

	basicAuth := thisObj.UserDefinedCredentials.BasicAuthentication
	credentials := fmt.Sprintf("%s:%s", basicAuth.UserName, basicAuth.Password)
	token := base64.StdEncoding.EncodeToString([]byte(credentials))

	return fmt.Sprintf("Basic %s", token)
}

// GenerateJWT generates a JWT bearer token using a Base64-encoded private key
func (thisObj *HttpRequest) GenerateJWToken(algorithm string, PrivateKey string, payload map[string]interface{}) (string, error) {
	var signingMethod jwt.SigningMethod

	// Select the signing method based on the algorithm
	switch algorithm {
	case "HS256":
		signingMethod = jwt.SigningMethodHS256
	case "HS384":
		signingMethod = jwt.SigningMethodHS384
	case "HS512":
		signingMethod = jwt.SigningMethodHS512
	case "RS256":
		signingMethod = jwt.SigningMethodRS256
	case "RS384":
		signingMethod = jwt.SigningMethodRS384
	case "RS512":
		signingMethod = jwt.SigningMethodRS512
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	// Create a new JWT token
	token := jwt.New(signingMethod)

	// Set the claims (payload)
	claims := token.Claims.(jwt.MapClaims)
	for key, value := range payload {
		claims[key] = value
	}

	// Sign the token
	var signedToken string
	var err error
	switch signingMethod.(type) {
	case *jwt.SigningMethodHMAC:
		// HMAC: Use the decoded key as a secret
		signedToken, err = token.SignedString(PrivateKey)
	case *jwt.SigningMethodRSA:
		// RSA: Parse the decoded key as an RSA private key
		privateKey, parseErr := jwt.ParseRSAPrivateKeyFromPEM([]byte(PrivateKey))
		if parseErr != nil {
			return "", fmt.Errorf("error parsing RSA private key: %v", parseErr)
		}
		signedToken, err = token.SignedString(privateKey)
	default:
		return "", errors.New("unsupported signing method")
	}

	if err != nil {
		return "", fmt.Errorf("error signing token: %v", err)
	}

	return signedToken, nil
}

func (thisObj *HttpRequest) ValidateCurl(parsedCurl string) (bool, error) {
	statusCode, _, err := thisObj.ExecuteCURL(parsedCurl)
	if err != nil {
		return false, errors.New("CURL command failed. Please check the URL and parameters.")
	}
	successfulStatuses := []string{"200", "201", "202", "204"}
	if slices.Contains(successfulStatuses, statusCode) {
		return true, nil
	} else {
		return false, fmt.Errorf("CURL command failed with HTTP status code %s. Check the CURL or Credentials.", statusCode)
	}
}

func (thisObj *HttpRequest) ExecuteCURL(curlCmd string) (string, string, error) {
	curlCmd = strings.ReplaceAll(curlCmd, "\\", "")
	statusCmd := curlCmd + ` -s -o /dev/null -w "%{http_code}"`
	statusOut, err := exec.Command("sh", "-c", statusCmd).Output() // Use sh shell to execute the command
	if err != nil {
		return "", "", fmt.Errorf("failed to execute curl for status: %v", err)
	}

	statusCode := strings.TrimSpace(string(statusOut))
	tempFile := fmt.Sprintf("response_body_%v.txt", uuid.New().String())
	bodyCmd := fmt.Sprintf(`%v -s -o %v`, curlCmd, tempFile)
	err = exec.Command("sh", "-c", bodyCmd).Run()
	if err != nil {
		return "", "", fmt.Errorf("failed to execute curl for body: %v", err)
	}
	defer os.Remove(tempFile)
	body, err := ioutil.ReadFile(tempFile)
	if err != nil {
		return "", "", fmt.Errorf("failed to read body response: %v", err)
	}

	return statusCode, string(body), nil
}

func (thisObj *HttpRequest) handleQuotesIfPresent(input string) string {
	if strings.HasPrefix(input, `"`) && strings.HasSuffix(input, `"`) {
		return strings.Trim(input, `"`)
	}
	if strings.HasPrefix(input, `'`) && strings.HasSuffix(input, `'`) {
		return strings.Trim(input, `'`)
	}
	return input
}

func (thisObj *HttpRequest) ValidateCredentialsType(credentialType, validationCURL string) (bool, string) {

	// Check 1: Placeholder in curl
	if strings.Contains(validationCURL, "<<"+credentialType) {
		return true, ""
	}
	// CCheck 2: redential checks
	switch credentialType {
	case "BasicAuthentication":
		auth := thisObj.GenerateBasicAuth()
		if strings.Contains(validationCURL, auth) {
			return true, ""
		}
		return false, "Credentials in ValidationCURL and Credential mismatch"

	case "BearerToken":
		bearerToken := thisObj.UserDefinedCredentials.BearerToken.Token

		if !strings.Contains(validationCURL, "Bearer") {
			return false, "Bearer type validation curl has no key word called 'Bearer' in 'Authoraization' header"
		}
		if strings.Contains(validationCURL, bearerToken) {
			return true, ""
		}
		return false, "Token in ValidationCURL and Credential mismatch"

	case "APIKey":
		apiKey := thisObj.UserDefinedCredentials.APIKey.APIKey
		if strings.Contains(validationCURL, apiKey) {
			return true, ""
		}
		return false, "APIKey in ValidationCURL and Credential mismatch"

	case "OAuth":
		clientSecret := thisObj.UserDefinedCredentials.OAuth.ClientSecret
		clientID := thisObj.UserDefinedCredentials.OAuth.ClientID

		var bodyData string
		if strings.Contains(validationCURL, "--data") {
			bodyData = strings.SplitN(validationCURL, "--data", 2)[1]
		} else if strings.Contains(validationCURL, "-d") {
			bodyData = strings.SplitN(validationCURL, "-d", 2)[1]
		} else if strings.Contains(validationCURL, "--form") {
			bodyData = strings.SplitN(validationCURL, "--form", 2)[1]
		}

		bodyData = thisObj.handleQuotesIfPresent(bodyData)
		if bodyData == "" {
			return false, "ValidationCURL has no request body; OAuth expects the 'url-encoded' request body."
		}

		clientSecretPattern := `(?i)\b(client[\W_]*secret|secret[\W_]*client)\b`
		clientIDPattern := `(?i)\b(client[\W_]*id|id[\W_]*client)\b`

		missMatchCred := []string{}

		// Check client secret
		if matched, _ := regexp.MatchString(clientSecretPattern, bodyData); matched {
			fullPattern := clientSecretPattern + `\s*=\s*` + regexp.QuoteMeta(clientSecret)
			if matched, _ := regexp.MatchString(fullPattern, bodyData); !matched {
				missMatchCred = append(missMatchCred, "ClientSecret")
			}
		}

		// Check client ID
		if matched, _ := regexp.MatchString(clientIDPattern, bodyData); matched {
			fullPattern := clientIDPattern + `\s*=\s*` + regexp.QuoteMeta(clientID)
			if matched, _ := regexp.MatchString(fullPattern, bodyData); !matched {
				missMatchCred = append(missMatchCred, "ClientID")
			}
		}

		if len(missMatchCred) > 0 {
			return false, strings.Join(missMatchCred, " and ") + " mismatch in ValidationCURL and Credential."
		}

		return true, ""
	}

	return false, "ValidationCURL and CredentialType mismatch"
}

func (thisObj *HttpRequest) ReplacePlaceholder(targetStr, placeholderPrefix string, valueDict map[string]interface{}) (string, error) {

	pattern := regexp.MustCompile(`<<` + regexp.QuoteMeta(placeholderPrefix) + `([^>]+)>>`)
	matches := pattern.FindAllStringSubmatch(targetStr, -1)

	if len(matches) == 0 {
		return targetStr, nil
	}

	for _, match := range matches {
		placeholderKey := match[1]
		value, err := thisObj.extractValue("<<"+placeholderKey+">>", valueDict)
		if err != nil {
			return "", err
		}

		if value != nil {
			targetStr = strings.ReplaceAll(targetStr, "<<"+placeholderPrefix+placeholderKey+">>", strings.TrimSpace(value.(string)))
		} else {
			fileType := strings.TrimSuffix(placeholderPrefix, "s")
			if fileType == "inputfile" {
				fileType = "InputFile"
			} else {
				fileType = "AppInfo"
			}
			return "", fmt.Errorf("Cannot resolve query '" + placeholderPrefix + placeholderKey + "'. " + fileType + " has no field " + placeholderKey + ".")
		}
	}

	return targetStr, nil
}

func (thisObj *HttpRequest) extractValue(query string, jsonData map[string]interface{}) (interface{}, error) {
	if strings.HasPrefix(query, "<<") && strings.HasSuffix(query, ">>") {
		cleanQuery := query[2 : len(query)-2]  // Remove the "<< >>"
		keys := strings.Split(cleanQuery, ".") // Split the query by "."

		var currentData interface{} = jsonData

		for i, key := range keys {
			if key == "" {
				continue
			}

			// Check if currentData is a map
			if dataMap, ok := currentData.(map[string]interface{}); ok {
				if strings.Contains(key, "[") && strings.Contains(key, "]") {
					// Handle key with index e.g., "key_name[0]"
					keyName := key[:strings.Index(key, "[")]
					indexStr := key[strings.Index(key, "[")+1 : strings.Index(key, "]")]

					// Handle "key_name[x]" case where x means iterate over all elements
					if indexStr == "x" {
						var tempResults []interface{}
						if listData, ok := dataMap[keyName].([]interface{}); ok {
							for _, subItem := range listData {
								subQuery := "<<" + strings.Join(keys[i+1:], ".") + ">>"
								result, err := thisObj.extractValue(subQuery, subItem.(map[string]interface{}))
								if err != nil {
									return nil, err
								}
								tempResults = append(tempResults, result)
							}
							return tempResults, nil
						} else {
							return nil, fmt.Errorf("expected a list for key: %s", keyName)
						}
					} else {
						// Handle key with specific index
						index, err := strconv.Atoi(indexStr)
						if err != nil {
							return nil, fmt.Errorf("invalid index in query: %s", indexStr)
						}

						if listData, ok := dataMap[keyName].([]interface{}); ok {
							if index >= 0 && index < len(listData) {
								currentData = listData[index]
							} else {
								return nil, fmt.Errorf("index out of range")
							}
						} else {
							return nil, fmt.Errorf("expected a list for key: %s", keyName)
						}
					}
				} else {
					// Handle normal key
					if val, exists := dataMap[key]; exists {
						currentData = val
					} else {
						return nil, fmt.Errorf("key not found: %s", key)
					}
				}
			} else {
				return nil, fmt.Errorf("expected map but got non-map value at key: %s", key)
			}
		}
		return currentData, nil
	}
	return query, nil
}

func (thisObj *HttpRequest) StructToMap(input interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// Get the value and type of the input
	val := reflect.ValueOf(input)

	// Check if the input is a pointer, and get the value it points to if so
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	// Ensure the input is a struct
	if val.Kind() != reflect.Struct {
		return nil, errors.New("input must be a struct or a pointer to a struct")
	}

	// Iterate through the struct's fields
	for i := 0; i < val.NumField(); i++ {
		field := val.Type().Field(i)
		value := val.Field(i)

		// Use the field's name as the key and its value as the value
		result[field.Name] = value.Interface()
	}

	return result, nil
}

func (thisObj *HttpRequest) ReplaceFunctionPlaceholders(stringData string) (string, error) {
	// Define the CEL environment
	env, err := cel.NewEnv(
		cel.Declarations(
			decls.NewVar("CURRENT_TIME", decls.Int),
			decls.NewVar("CURRENT_DATE", decls.String),
		),
	)
	if err != nil {
		return "", fmt.Errorf("Failed to create CEL environment: %v", err)
	}

	// Supported Functions
	inputs := map[string]interface{}{
		"CURRENT_TIME": int(time.Now().Unix()),          // Current Unix timestamp
		"CURRENT_DATE": time.Now().Format(time.RFC3339), // Current date and time in ISO 8601 format
	}

	pattern, err := regexp.Compile("<<(.*?)>>")
	if err != nil {
		return "", fmt.Errorf("Failed to extract placeholders: %v", err)
	}

	matches := pattern.FindAllStringSubmatch(stringData, -1)

	updatedStringData := stringData
	for _, match := range matches {

		expression := match[1]

		// Parse and check the expression
		ast, issues := env.Compile(expression)
		if issues != nil && issues.Err() != nil {
			return "", fmt.Errorf("Compile issues: %v", issues.Err())
		}

		// Create a program from the AST
		program, err := env.Program(ast)
		if err != nil {
			return "", fmt.Errorf("Failed to create program: %v", err)
		}

		// Evaluate the expression
		result, _, err := program.Eval(inputs)
		if err != nil {
			return "", fmt.Errorf("Failed to evaluate expression: %v", err)
		}

		updatedStringData = strings.ReplaceAll(updatedStringData, match[0], result.ConvertToType(types.StringType).Value().(string))
	}

	return updatedStringData, nil
}
