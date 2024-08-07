package credentials

import (
	"context"
	"cowlibrary/constants"
	"cowlibrary/utils"
	"cowlibrary/vo"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/iancoleman/strcase"

	"github.com/go-resty/resty/v2"
	"gopkg.in/yaml.v2"
)

type CredentialsHandler struct {
	Context context.Context
}

func (credentialsHandler *CredentialsHandler) Init(namePointer *vo.CowNamePointersVO, additionalInfo *vo.AdditionalInfo) []*vo.ErrorDetailVO {

	err := utils.Validate.Struct(namePointer)
	errorDetails := utils.GetValidationError(err)
	if len(errorDetails) > 0 {
		return errorDetails
	}

	errorDetails = make([]*vo.ErrorDetailVO, 0)

	if utils.IsFolderNotExist(additionalInfo.PolicyCowConfig.PathConfiguration.CredentialsPath) {
		if err := os.MkdirAll(additionalInfo.PolicyCowConfig.PathConfiguration.CredentialsPath, os.ModePerm); err != nil {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorFolderPathMissing})
			return errorDetails
		}
	}

	credName := strcase.ToCamel(namePointer.Name)
	credNameLower := strings.ToLower(namePointer.Name)

	credYAML := strings.NewReplacer("{{CREDENTIAL_CLASS_NAME}}", credName,
		"{{CREDENTIAL_CLASS_TAG}}", credNameLower,
		"{{CREDENTIAL_VERSION}}", namePointer.Version,
	).Replace(constants.CredentialYAML)

	credFilePath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.CredentialsPath, namePointer.Name+"_v_"+strings.ReplaceAll(namePointer.Version, ".", "_")+".yaml")

	if utils.IsFileExist(credFilePath) && !additionalInfo.CanOverride {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCredentialsAlreadyAvailable})
		return errorDetails
	}

	if err := os.WriteFile(credFilePath, []byte(credYAML), os.ModePerm); err != nil {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotCreateCredential})
		return errorDetails
	}

	return nil

}

func (credentialsHandler *CredentialsHandler) Create(credential *vo.UserDefinedCredentialVO, additionalInfo *vo.AdditionalInfo) []*vo.ErrorDetailVO {

	err := utils.Validate.Struct(credential)
	errorDetails := utils.GetValidationError(err)
	if len(errorDetails) > 0 {
		return errorDetails
	}
	errorDetails = make([]*vo.ErrorDetailVO, 0)

	if additionalInfo == nil || additionalInfo.PolicyCowConfig == nil || additionalInfo.PolicyCowConfig.PathConfiguration == nil && utils.IsEmpty(additionalInfo.PolicyCowConfig.PathConfiguration.DeclarativePath) {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorFolderPathMissing})
		return errorDetails
	}

	if utils.IsEmpty(credential.Meta.Version) {
		credential.Meta.Version = constants.VersionLatest
	}

	folderPath, credentialsPath, isAlreadyAvailable := GetCredPathWithAvailability(credential, additionalInfo)

	if isAlreadyAvailable && !credential.IsVersionToBeOverride {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCredentialsAlreadyAvailable})
		return errorDetails
	}

	if additionalInfo.ApplictionScopeConfigVO == nil || len(additionalInfo.ApplictionScopeConfigVO.FileData) < 2 {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorFileDataMissing})
		return errorDetails
	}

	attributes := make([]*vo.CredentialAttributesVO, 0)

	attributesMap := make(map[string]*vo.CredentialAttributesVO, 0)

	attributeKeys := make([]string, 0)

	for _, attribute := range credential.Spec.Attributes {
		if _, ok := attributesMap[attribute.Name]; !ok {
			attributesMap[attribute.Name] = attribute
			attributeKeys = append(attributeKeys, attribute.Name)
		} else {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCredentialDuplicateAttribute, Location: attribute.Name})
		}
	}

	if len(errorDetails) > 0 {
		return errorDetails
	}

	if extendedCredentials := credential.Spec.Extends; len(extendedCredentials) > 0 {
		// INFO : We need to override the attributes(if any) based on the declaration order
		utils.ReverseSlice(extendedCredentials)

		for _, parentCredential := range extendedCredentials {

			name, version := parentCredential.Name, parentCredential.Version

			if utils.IsEmpty(version) {
				version = constants.VersionDefault
			}

			if name == credential.Meta.Name && version == credential.Meta.Version {
				errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCircularDependency, Location: fmt.Sprintf("%s::%s", name, version)})
			}

			if utils.IsEmpty(name) {
				errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotFindCredential})
				return errorDetails
			} else {
				generatedFile := filepath.Join(credentialsPath, strings.ToLower(name), version, constants.YAMLTypeGenerated)
				if utils.IsFileNotExist(generatedFile) {
					errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotFindCredential, Location: name})
					return errorDetails
				}
				parentCrdentialByts, err := os.ReadFile(generatedFile)
				if err != nil {
					errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotReadCredential, Location: name})
				} else {
					parentCredentialVO := &vo.UserDefinedCredentialVO{}
					err = yaml.Unmarshal(parentCrdentialByts, parentCredentialVO)
					if err != nil {
						errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotUnmarshalCredential, Location: name})
						return errorDetails
					} else {
						if parentCredentialVO.Meta != nil && parentCredentialVO.Meta.Name != name {
							errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotFindCredential, Location: name})
							return errorDetails
						}
						if parentCredentialVO.Spec != nil && len(parentCredentialVO.Spec.Attributes) > 0 {
							for _, parentAttribute := range parentCredentialVO.Spec.Attributes {
								if _, ok := attributesMap[parentAttribute.Name]; !ok {
									attributeKeys = append(attributeKeys, parentAttribute.Name)
									attributesMap[parentAttribute.Name] = parentAttribute
								}
							}
						}
					}
				}
			}
		}

	}

	var validate = validator.New()

	if len(attributesMap) > 0 {
		for _, attribute := range attributesMap {
			dataType := ""

			dataTypeInterface, err := attribute.DataType.MarshalYAML()

			if err == nil {
				dataType = dataTypeInterface.(string)
			}

			if utils.IsNotEmpty(attribute.DefaultValue) && len(attribute.AllowedValues) > 0 && !utils.SliceContains(attribute.AllowedValues, attribute.DefaultValue) {
				errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "Allowed values should contain the default value", Location: attribute.Name})
			}

			if utils.IsNotEmpty(dataType) {

				if dataType == constants.DeclarativesDataTypeFILE {
					if attribute.MultiSelect {
						errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorMultiSelectNotSupportedForFile, Location: attribute.Name})
						return errorDetails
					}

					if attribute.Secret {
						errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorFileTypeCannotBeSecured, Location: attribute.Name})
						return errorDetails
					}

					if len(attribute.AllowedValues) > 0 {
						errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "Allowed values can't define for a file value", Location: attribute.Name})
						return errorDetails
					}

					if utils.IsNotEmpty(attribute.DefaultValue) {
						errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "You can't set default value for a file type attribute", Location: attribute.Name})
						return errorDetails
					}
				}

				if dataType == constants.DeclarativesDataTypeINT {
					for _, val := range attribute.AllowedValues {
						if _, err := strconv.Atoi(val); err != nil {
							errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "Allowed values can contain only integers", Location: attribute.Name})
							return errorDetails
						}
					}

					if utils.IsNotEmpty(attribute.DefaultValue) {
						if _, err := strconv.Atoi(attribute.DefaultValue); err != nil {
							errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "Only int values can be set in default value", Location: attribute.Name})
						}
					}
				}

				if dataType == constants.DeclarativesDataTypeFLOAT {
					if len(attribute.AllowedValues) > 0 {
						if err := validate.Var(attribute.AllowedValues, "required,dive,numeric"); err != nil {
							errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "Allowed values can contain only numbers", Location: attribute.Name})
						}

						if utils.IsNotEmpty(attribute.DefaultValue) {
							if err := validate.Var(attribute.DefaultValue, "required,numeric"); err != nil {
								errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "Only float value can be set in default value", Location: attribute.Name})
							}
						}

					}

				}
			}

			attributes = append(attributes, attribute)
		}
	}

	if len(errorDetails) > 0 {
		return errorDetails
	}

	attributes = make([]*vo.CredentialAttributesVO, 0)

	for _, attrName := range attributeKeys {
		if attr, ok := attributesMap[attrName]; ok {
			attributes = append(attributes, attr)
		}
	}

	credential.Spec.Attributes = attributes

	credential.Spec.Extends = nil

	fileByts, err := yaml.Marshal(credential)

	if err != nil {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotUnmarshalCredential})
		return errorDetails
	}

	if utils.IsFolderNotExist(folderPath) {
		err = os.MkdirAll(folderPath, os.ModePerm)
		if err != nil {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotCreateCredentialsFolder})
			return errorDetails
		}
	}

	errorDetails = utils.CreateDeclarativeFiles(additionalInfo.ApplictionScopeConfigVO.FileData, fileByts, folderPath)
	if len(errorDetails) > 0 {
		return errorDetails
	}

	return nil
}

func GetCredPathWithAvailability(credential *vo.UserDefinedCredentialVO, additionalInfo *vo.AdditionalInfo) (folderPath, credentialsPath string, isAlreadyAvailable bool) {
	return utils.GetDeclarativePathWithAvailability(credential.Meta, additionalInfo, constants.UserDefinedCredentialsPath)
}

func IsCredentialAlreadyPresent(credential *vo.UserDefinedCredentialVO, additionalInfo *vo.AdditionalInfo) bool {
	return utils.IsDeclarativesAlreadyPresent(credential.Meta, additionalInfo, constants.UserDefinedCredentialsPath)
}

func PublishCredential(credentialPointer *vo.CredentialsPointerVO, additionalInfo *vo.AdditionalInfo) []*vo.ErrorDetailVO {
	errorDetails := make([]*vo.ErrorDetailVO, 0)
	headerMap, err := utils.GetAuthHeader(additionalInfo)
	if err != nil {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotGetAuthToken})
		return errorDetails
	}

	return PublishCredentialHelper(credentialPointer, additionalInfo, headerMap)
}

func PublishCredentialHelper(credentialPointer *vo.CredentialsPointerVO, additionalInfo *vo.AdditionalInfo, headerMap map[string]string) []*vo.ErrorDetailVO {
	errorDetails := make([]*vo.ErrorDetailVO, 0)
	credentialsPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.DeclarativePath, constants.UserDefinedCredentialsPath)
	name, version := credentialPointer.Name, credentialPointer.Version
	if utils.IsEmpty(version) {
		version = constants.VersionDefault
	}

	if utils.IsEmpty(name) {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotFindCredential, Location: name})
		return errorDetails
	} else {
		credPath := filepath.Join(credentialsPath, name, version, constants.YAMLTypeGenerated)
		if utils.IsFileNotExist(credPath) {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotFindCredential, Location: name})
			return errorDetails
		}
		credentialByts, err := os.ReadFile(credPath)
		if err != nil {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotReadCredential, Location: name})
			return errorDetails
		}
		credentialsVO := &vo.UserDefinedCredentialVO{}
		err = yaml.Unmarshal(credentialByts, credentialsVO)
		if err != nil {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotUnmarshalCredential, Location: name})
			return errorDetails
		}

		credCollection := &vo.Collection{}
		creds := make([]*vo.UserDefinedCredentialVO, 0)
		credCollection.Items = &creds

		errorData := json.RawMessage{}

		client := resty.New()
		url := fmt.Sprintf("%s/v1/cred-configs", utils.GetCowAPIEndpoint(additionalInfo))
		resp, err := client.R().SetHeaders(headerMap).SetQueryParams(map[string]string{
			"name":    credentialsVO.Meta.Name,
			"version": credentialsVO.Meta.Version,
		}).SetResult(credCollection).SetError(&errorData).Get(url)

		if err != nil || resp.StatusCode() != http.StatusOK {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "cannot get the credentials"})
			return errorDetails
		}

		if len(errorData) > 4 {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: string(errorData)})
			return errorDetails
		}

		if !additionalInfo.CanOverride {

			if len(creds) > 0 {
				errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: fmt.Sprintf("%s for %s:%s", constants.ErrorCredAlreadyPresent, credentialPointer.Name, credentialPointer.Version)})
				return errorDetails
			}
		}

		if len(creds) > 1 {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: fmt.Sprintf("more than one cred has been present for %s:%s", credentialPointer.Name, credentialPointer.Version)})
			return errorDetails
		}

		responseVO := &vo.CowResponseVO{}

		request := client.R().SetHeaders(headerMap).SetHeader("Content-Type", "text/yaml").
			SetBody(credentialByts).SetResult(responseVO).SetError(&errorData)

		if len(creds) == 0 {
			resp, err = request.Post(url)

		} else {
			url += "/" + creds[0].ID
			resp, err = request.Put(url)
		}

		if err != nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusCreated) || utils.IsEmpty(responseVO.ID) {
			if len(errorData) > 4 {
				errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: string(errorData)})
				return errorDetails
			}

			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "cannot publish the credential"})
			return errorDetails
		}

		if len(errorData) > 4 {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: string(errorData)})
			return errorDetails
		}

	}

	return nil

}
