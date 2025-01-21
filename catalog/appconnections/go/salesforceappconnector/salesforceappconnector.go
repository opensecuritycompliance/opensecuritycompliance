package salesforceappconnector

import (
	"cowlibrary/vo"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

type CustomType struct {
	ValidationCURL string   `json:"validationCURL" yaml:"ValidationCURL"`
	CredentialJson vo.Bytes `json:"credentialJson" yaml:"CredentialJson"`
}

type UserDefinedCredentials struct {
	CustomType CustomType `json:"customType" yaml:"CustomType"`
}

type LinkedApplications struct {
}

type SalesforceAppConnector struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"appPort"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
	LinkedApplications     *LinkedApplications     `json:"linkedApplications" yaml:"linkedApplications"`
}

func (thisObj *SalesforceAppConnector) Validate() (bool, error) {

	credsCustomType := thisObj.UserDefinedCredentials.CustomType
	if credsCustomType.ValidationCURL != "" {
		return thisObj.ValidateCustomType()
	}

	return false, errors.New("invalid Credential Type")
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

// INFO : You can implement your own implementation for the class

func (thisObj *SalesforceAppConnector) ValidateCustomType() (bool, error) {

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

func (thisObj *SalesforceAppConnector) ReplacePlaceholder(targetStr, placeholderPrefix string, valueDict map[string]interface{}) (string, error) {

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

func (thisObj *SalesforceAppConnector) ValidateCurl(parsedCurl string) (bool, error) {
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

func (thisObj *SalesforceAppConnector) extractValue(query string, jsonData map[string]interface{}) (interface{}, error) {
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

func (thisObj *SalesforceAppConnector) ExecuteCURL(curlCmd string) (string, string, error) {
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
