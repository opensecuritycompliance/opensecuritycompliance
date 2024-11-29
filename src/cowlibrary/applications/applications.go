package applications

import (
	"bufio"
	"context"
	"cowlibrary/constants"
	"cowlibrary/credentials"
	"cowlibrary/task"
	"cowlibrary/utils"
	"cowlibrary/vo"
	"encoding/json"
	"errors"
	"fmt"
	"go/format"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/go-resty/resty/v2"
	"github.com/iancoleman/strcase"
	"github.com/otiai10/copy"

	"gopkg.in/yaml.v2"
)

type GoApplicationHandler struct {
	Context context.Context
}

type Applications interface {
	Create(applicationVO *vo.UserDefinedApplicationVO, additionalInfo *vo.AdditionalInfo) []*vo.ErrorDetailVO
}

func GetApplication(language constants.SupportedLanguage) Applications {
	switch language {
	case constants.SupportedLanguagePython:
		return &PythonApplicationHandler{}
	default:
		return &GoApplicationHandler{}
	}
}

type credInfo struct {
	Credential *vo.UserDefinedCredentialVO
	Repeated   bool
}

func Init(namePointer *vo.CowNamePointersVO, additionalInfo *vo.AdditionalInfo) []*vo.ErrorDetailVO {

	err := utils.Validate.Struct(namePointer)
	errorDetails := utils.GetValidationError(err)
	if len(errorDetails) > 0 {
		return errorDetails
	}

	errorDetails = make([]*vo.ErrorDetailVO, 0)

	if utils.IsFolderNotExist(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationClassPath) {
		if err := os.MkdirAll(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationClassPath, os.ModePerm); err != nil {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorFolderPathMissing})
			return errorDetails
		}
	}

	appName := strcase.ToCamel(namePointer.Name)
	appNameLower := strings.ToLower(namePointer.Name)

	appYAML := strings.NewReplacer("{{APPLICATION_CLASS_NAME}}", appName,
		"{{APPLICATION_CLASS_TAG}}", appNameLower,
		"{{APPLICATION_VERSION}}", namePointer.Version,
	).Replace(constants.ApplicationYAML)

	credentialTypesYAML := ""
	for _, cred := range additionalInfo.CredentialInfo {
		credentialTypesYAML += fmt.Sprintf("  - name: %s\n    version: %s\n", cred.Name, cred.Version)
	}
	appYAML = strings.ReplaceAll(appYAML, "{{CREDENTIAL_TYPES}}", credentialTypesYAML)

	linkedApplicationYAML := ""
	for _, linkedApp := range additionalInfo.LinkedApplications {
		linkedApplicationYAML += fmt.Sprintf("  - name: %s\n", linkedApp.Name)
	}
	// appYAML = strings.ReplaceAll(appYAML, "{{LINKED_APPLICATION_NAMES}}", linkedApplicationYAML)

	linkedApplicationClassessYAML := ""
	if linkedApplicationYAML != "" {
		linkedApplicationClassessYAML = strings.NewReplacer("{{LINKED_APPLICATION_NAMES}}", linkedApplicationYAML).Replace(constants.LinkedApplicationClassYaml)
	}
	appYAML = strings.ReplaceAll(appYAML, "{{LINKED_APPLICATION_CLASSES_YAML}}", linkedApplicationClassessYAML)

	appFilePath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationClassPath, utils.GetYAMLFileNameWithoutVersion(namePointer))

	if utils.IsFileExist(appFilePath) && !additionalInfo.CanOverride {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCredentialsAlreadyAvailable})
		return errorDetails
	}

	if err := os.WriteFile(appFilePath, []byte(appYAML), os.ModePerm); err != nil {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotCreateCredential})
		return errorDetails
	}

	return nil

}

func (applicationHandler *GoApplicationHandler) Create(applicationVO *vo.UserDefinedApplicationVO, additionalInfo *vo.AdditionalInfo) []*vo.ErrorDetailVO {

	credentialMap, errorDetails := HandleDecalrativesCreation(applicationVO, additionalInfo)
	if len(errorDetails) > 0 {
		return errorDetails
	}

	err := applicationHandler.GenerateApplicationStruct(applicationVO, credentialMap, additionalInfo)
	if err != nil {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotCreateApplication})
		return errorDetails
	}

	return nil
}

func (applicationHandler *GoApplicationHandler) GenerateApplicationStruct(applicationVO *vo.UserDefinedApplicationVO, credentialsMap map[string]*credInfo, additionalInfo *vo.AdditionalInfo) error {

	credentialsStructs := make([]string, 0)
	credentialDefs := make([]string, 0)

	importCowVO := false
	importCowVOstr := ``

	var linkedAppsImports, linkedAppsStructElements strings.Builder
	for _, app := range applicationVO.Spec.LinkableApplicationClasses {
		appNameSmall := strings.ToLower(app.Name)
		linkedAppsImports.WriteString(fmt.Sprintf(`%s "appconnections/%s"`+"\n", appNameSmall, appNameSmall))
		linkedAppsStructElements.WriteString(fmt.Sprintf("	%s.%s `"+`yaml:",inline"`+"`\n", appNameSmall, app.Name))
	}
	// {{IMPORT_PACKAGES}}
	var validateAttributes strings.Builder
	for credentialName, credential := range credentialsMap {
		credentialName = strcase.ToCamel(credentialName)
		structDef := `    ` + credentialName + `	`
		// INFO : As of now no pointer
		if credential.Repeated {
			structDef += `[]`
		}
		// INFO : As of now ,omitempty is not added
		credName := strcase.ToLowerCamel(credentialName)
		structDef += credentialName + "  `" + `json:"` + credName + `" yaml:"` + credentialName + `"` + "`"
		credentialsStructs = append(credentialsStructs, structDef)
		credStruct := applicationHandler.GenerateCredentialStruct(credentialName, credential.Credential)
		if strings.Contains(credStruct, "vo.Bytes") {
			importCowVO = true
		}
		credentialDefs = append(credentialDefs, applicationHandler.GenerateCredentialStruct(credentialName, credential.Credential))

		validateAttributes.WriteString(fmt.Sprintf(`
		func (%s *%s) ValidateAttributes() string {
			var emptyAttributes []string
			errorResultStr := ""`, strings.ToLower(credentialName), credentialName))

		for _, attr := range credential.Credential.Spec.Attributes {
			if attr.Required {
				attrName := strcase.ToCamel(attr.Name)
				// attrType := strings.ToLower(attr.DataType.())
				switch attr.DataType {
				case "string":
					validateAttributes.WriteString(fmt.Sprintf(`
					if %s.%s == "" {
						emptyAttributes = append(emptyAttributes, "%s")
					}`, strings.ToLower(credentialName), attrName, attrName))
				case "int":
					validateAttributes.WriteString(fmt.Sprintf(`
					if %s.%s < 0 {
						emptyAttributes = append(emptyAttributes, "%s")
					}`, strings.ToLower(credentialName), attrName, attrName))
				case "float64":
					validateAttributes.WriteString(fmt.Sprintf(`
					if %s.%s < 0.0 {
						emptyAttributes = append(emptyAttributes, "%s")
					}`, strings.ToLower(credentialName), attrName, attrName))
				case "Bytes":
					validateAttributes.WriteString(fmt.Sprintf(`
					if len(%s.%s) == 0 {
						emptyAttributes = append(emptyAttributes, "%s")
					}`, strings.ToLower(credentialName), attrName, attrName))
				}
			}
		}

		validateAttributes.WriteString(`
		if len(emptyAttributes) > 0 {
			errorResultStr = fmt.Sprintf("Invalid Credentials: %s", strings.Join(emptyAttributes, ", ") + " is empty")
		}
		return errorResultStr
	}
	`)

	}

	applicationStructName := strcase.ToCamel(applicationVO.Meta.Name)

	if importCowVO {
		importCowVOstr = `import (
			"cowlibrary/vo"
		)`
	}

	replacer := strings.NewReplacer("{{PACKAGE_NAME}}", strings.ToLower(applicationVO.Meta.Name),
		"{{USER_DEFINED_CREDENTIAL_STRUCT_VO}}", strings.Join(credentialDefs, "\n"),
		"{{APPLICATION_STRUCT_NAME}}", applicationStructName,
		"{{IMPORT_PACKAGES}}", importCowVOstr,
		"{{USER_DEFINED_CREDENTIALS}}", strings.Join(credentialsStructs, "\n"),
		"{{VALIDATE_ATTRIBUTES}}", validateAttributes.String(),
		"{{LINKED_APPLICATIONS}}", linkedAppsStructElements.String(),
		"{{LINKED_APPLICATIONS_IMPORTS}}", linkedAppsImports.String(),
	)

	fileData := replacer.Replace(constants.ApplicationStruct)

	formattedFileBytes, err := format.Source([]byte(fileData))
	if err != nil {
		return err
	}

	if utils.IsEmpty(additionalInfo.PolicyCowConfig.PathConfiguration.AppConnectionPath) {
		additionalInfo.PolicyCowConfig.PathConfiguration.AppConnectionPath = constants.CowDataAppConnectionPath
	}

	packageName := strings.ToLower(applicationVO.Meta.Name)

	// folderPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.AppConnectionPath, "go", packageName, applicationVO.Meta.Version)

	folderPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.AppConnectionPath, "go", packageName)

	if utils.IsFolderNotExist(folderPath) {
		err = os.MkdirAll(folderPath, os.ModePerm)
		if err != nil {
			return err
		}
	}

	err = os.WriteFile(filepath.Join(folderPath, packageName+".go"), formattedFileBytes, os.ModePerm)
	if err != nil {
		return err
	}

	taskName := strcase.ToCamel("Validate" + applicationStructName)

	additionalInfo.IsTasksToBePrepare = true

	validationTask := filepath.Join(folderPath, taskName)

	if utils.IsFolderExist(validationTask) {
		os.RemoveAll(validationTask)
	}

	err = (&task.GoTask{}).InitTask(taskName, folderPath, nil, additionalInfo)

	if err != nil {
		return err
	}

	metaFilePath := filepath.Join(validationTask, "__meta.yaml")
	err = os.Remove(metaFilePath)
	if err != nil {
		return err
	}

	err = (&task.GoTask{}).PrepareTask(validationTask, additionalInfo)

	if err != nil {
		return err
	}

	err = CreateTaskInputYAMLWithAppConfig(validationTask, applicationVO, credentialsMap)
	if err != nil {
		return err
	}

	return applicationHandler.ModifyAutoGeneratedTaskWithBaseValidationTask(taskName, folderPath, applicationVO)

}

func (applicationHandler *GoApplicationHandler) GenerateCredentialStruct(structName string, credential *vo.UserDefinedCredentialVO) string {

	structStr := `type ` + structName + ` struct{`

	for _, attribute := range credential.Spec.Attributes {
		structStr += "\n" + ` ` + strcase.ToCamel(attribute.Name) + `   `

		if attribute.MultiSelect {
			structStr += `[]`
		}

		dataType := string(attribute.DataType)

		if dataType == "Bytes" {
			dataType = "vo.Bytes"
		}

		attrName := strcase.ToLowerCamel(attribute.Name)

		// INFO : As of now ,omitempty is not added
		structStr += dataType + "`" + `json:"` + attrName + `"` + ` yaml:"` + attribute.Name + `"` + "`"
	}

	structStr += "\n }"

	return structStr

}

func (applicationHandler *GoApplicationHandler) ModifyAutoGeneratedTaskWithBaseValidationTask(taskName, folderPath string, applicationVO *vo.UserDefinedApplicationVO) error {

	taskFolderPath := filepath.Join(folderPath, taskName)

	if utils.IsFolderNotExist(taskFolderPath) {
		return fmt.Errorf("cannot find the task path of %s", taskName)
	}

	appPackageName := strings.ToLower(applicationVO.Meta.Name)

	replacer := strings.NewReplacer("{{APPLICATION_PACKAGE_NAME}}", appPackageName,
		"{{VERSION}}", applicationVO.Meta.Version,
		"{{APPLICATION_PACKAGE_NAME}}", appPackageName,
		"{{APP_STRUCT_NAME}}", strcase.ToCamel(applicationVO.Meta.Name))

	if err := os.WriteFile(filepath.Join(taskFolderPath, "task_service_structs.go"), []byte(replacer.Replace(constants.ValidateTaskStruct)), os.ModePerm); err != nil {
		return err
	}
	taskServiceFile := strings.ReplaceAll(constants.ValidateTask, "{{TASK_NAME}}", taskName)

	if err := os.WriteFile(filepath.Join(taskFolderPath, "task_service.go"), []byte(taskServiceFile), os.ModePerm); err != nil {
		return err
	}

	os.Remove(filepath.Join(taskFolderPath, constants.AutoGeneratedFilePrefix+"file_store.go"))

	goModFilePath := filepath.Join(taskFolderPath, "go.mod")

	os.Remove(goModFilePath)

	commandSeq := fmt.Sprintf("go mod init %s", taskName)

	cmd := exec.Command("bash", "-c", commandSeq)
	cmd.Dir = taskFolderPath
	_, err := cmd.Output()
	if err != nil {
		return err
	}

	return applicationHandler.GoModModifyWithLocalLibraries(taskFolderPath)

}

func (applicationHandler *GoApplicationHandler) GoModModifyWithLocalLibraries(taskPath string) error {
	goModFilePath := filepath.Join(taskPath, "go.mod")

	if utils.IsFileExist(goModFilePath) {

		file, err := os.OpenFile(goModFilePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			return err
		}
		defer file.Close()
		// Create a new bufio.Writer for efficient writing
		writer := bufio.NewWriter(file)
		// Append the string to the next line
		_, err = fmt.Fprint(writer, constants.ValidateTaskGoModLibraryPointers)
		if err != nil {
			return err
		}
		// Flush the buffer to ensure data is written to the file
		err = writer.Flush()
		if err != nil {
			return err
		}

	}

	return nil
}

func GetAppPathWithAvailability(app *vo.UserDefinedApplicationVO, additionalInfo *vo.AdditionalInfo) (folderPath, credentialsPath string, isAlreadyAvailable bool) {
	return utils.GetDeclarativePathWithAvailability(app.Meta, additionalInfo, constants.UserDefinedApplicationPath)
}

func IsAppAlreadyPresent(meta *vo.CowMetaVO, additionalInfo *vo.AdditionalInfo) bool {
	return utils.IsDeclarativesAlreadyPresent(meta, additionalInfo, constants.UserDefinedApplicationPath)
}

func ValidateLinkedApplications(spec *vo.CowApplicationSpecVO, additionalInfo *vo.AdditionalInfo, yamlFilePath string) *vo.ErrorDetailVO {
	return utils.ValidateLinkedApplications(spec, additionalInfo, yamlFilePath)
}

func IsAppAlreadyPresentWithoutVersion(meta *vo.CowMetaVO, additionalInfo *vo.AdditionalInfo) bool {
	return utils.IsDeclarativesAlreadyPresentWithoutVersion(meta, additionalInfo, constants.UserDefinedApplicationPath)
}

func GetLinkedApplications(namePointersVO *vo.CowNamePointersVO, additionalInfo *vo.AdditionalInfo) ([]*vo.CowNamePointersVO, *vo.ErrorDetailVO) {
	folderName := strings.ToLower(namePointersVO.Name)
	appDeclarativesPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.DeclarativePath, constants.UserDefinedApplicationPath)
	folderPath := filepath.Join(appDeclarativesPath, folderName)

	fileByts, err := os.ReadFile(filepath.Join(folderPath, constants.YAMLTypeSrc))
	if err != nil {
		return nil, &vo.ErrorDetailVO{Issue: constants.ErrorCannotReadApplication}
	}
	applicationVO := &vo.UserDefinedApplicationVO{}
	err = yaml.Unmarshal(fileByts, applicationVO)
	if err != nil {
		return nil, &vo.ErrorDetailVO{Issue: constants.ErrorCannotUnmarshalApplication}
	}
	return applicationVO.Spec.LinkableApplicationClasses, nil
}

func PublishApplication(namePointersVO *vo.CowNamePointersVO, additionalInfo *vo.AdditionalInfo) []*vo.ErrorDetailVO {

	errorDetails := make([]*vo.ErrorDetailVO, 0)
	// if utils.IsEmpty(namePointersVO.Version) {
	// 	namePointersVO.Version = constants.SemanticVersionDefault
	// }

	if IsAppAlreadyPresentWithoutVersion(&vo.CowMetaVO{Name: namePointersVO.Name}, additionalInfo) {
		folderName := strings.ToLower(namePointersVO.Name)

		// credentialsPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.DeclarativePath, constants.UserDefinedCredentialsPath)

		appDeclarativesPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.DeclarativePath, constants.UserDefinedApplicationPath)

		// folderPath := filepath.Join(appDeclarativesPath, folderName, strings.ToLower(namePointersVO.Version))
		folderPath := filepath.Join(appDeclarativesPath, namePointersVO.Name)
		fileByts, err := os.ReadFile(filepath.Join(folderPath, constants.YAMLTypeGenerated))
		if err != nil {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotReadApplication})
			return errorDetails
		}

		applicationVO := &vo.UserDefinedApplicationVO{}

		err = yaml.Unmarshal(fileByts, applicationVO)

		if err != nil {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotUnmarshalApplication})
			return errorDetails
		}

		headerMap, err := utils.GetAuthHeader(additionalInfo)
		if err != nil {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotGetAuthToken})
			return errorDetails
		}

		apiEndpoint := utils.GetCowAPIEndpoint(additionalInfo)

		client := resty.New()
		url := fmt.Sprintf("%s/v1/app-configs", apiEndpoint)

		collection := &vo.Collection{}

		apps := make([]*vo.UserDefinedApplicationVO, 0)
		collection.Items = &apps
		errorData := json.RawMessage{}

		resp, err := client.R().SetHeaders(headerMap).SetQueryParams(map[string]string{
			"name":    applicationVO.Meta.Name,
			"version": applicationVO.Meta.Version,
		}).SetResult(collection).SetError(&errorData).Get(url)

		if err != nil || resp.StatusCode() != http.StatusOK {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotGetApplication})
			return errorDetails
		}

		if len(errorData) > 4 {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: string(errorData)})
			return errorDetails
		}

		if !additionalInfo.CanOverride {

			if len(apps) > 0 {
				errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorAppAlreadyPresent})
				return errorDetails
			}
		}

		if len(apps) > 1 {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorMoreThanOneAppPresent})
			return errorDetails
		}

		s := spinner.New(spinner.CharSets[38], 100*time.Millisecond) // Build our new spinner
		s.Prefix = "Publishing ..."

		s.Start()

		defer func(spinr *spinner.Spinner) {
			if spinr.Active() {
				spinr.Stop()
			}
		}(s)

		additionalInfo.CanOverride = true

		for _, credential := range applicationVO.Spec.CredentialTypes {
			s.Prefix = fmt.Sprintf("publishing credential %s:%s", credential.Name, credential.Version)
			credErrorDetials := credentials.PublishCredentialHelper(credential, additionalInfo, headerMap)
			if len(credErrorDetials) > 0 {
				errorDetails = append(errorDetails, credErrorDetials...)
				s.Prefix = fmt.Sprintf("publishing credential %s:%s has been failed", credential.Name, credential.Version)
				return errorDetails
			}
			s.Prefix = fmt.Sprintf("published credential %s:%s has been succeed", credential.Name, credential.Version)
		}

		// packageName := strings.ToLower(applicationVO.Meta.Name)

		if utils.IsEmpty(additionalInfo.Language) {
			if utils.IsFolderExist(filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.AppConnectionPath, "go", folderName)) {
				additionalInfo.Language = "go"
			} else {
				additionalInfo.Language = "python"
			}
		}

		// appConnectionPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.AppConnectionPath, additionalInfo.Language, folderName, applicationVO.Meta.Version)

		appConnectionPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.AppConnectionPath, additionalInfo.Language, folderName)

		allAppsSorucePath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.AppConnectionPath, additionalInfo.Language)
		if additionalInfo.Language == "python" {
			appConnectionPath = filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.AppConnectionPath, additionalInfo.Language, filepath.Base(additionalInfo.PolicyCowConfig.PathConfiguration.AppConnectionPath), folderName)
			allAppsSorucePath = filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.AppConnectionPath, additionalInfo.Language, filepath.Base(additionalInfo.PolicyCowConfig.PathConfiguration.AppConnectionPath))
		}

		taskName := strcase.ToCamel("Validate" + strcase.ToCamel(applicationVO.Meta.Name))
		applicationVO.Spec.Validation.TaskName = taskName

		binaryFileName := taskName

		taskFolder := filepath.Join(appConnectionPath, taskName)

		workerNodeType := "bin"

		if utils.IsFolderExist(taskFolder) {
			s.Prefix = "Publishing the validation task ...."

			if utils.IsGoTask(taskFolder) {

				commandSeq := ``
				if utils.IsFileNotExist(filepath.Join(taskFolder, "go.mod")) {
					commandSeq += fmt.Sprintf("go mod init  %s && ", taskName)
				} else {
					commandSeq += fmt.Sprintf("go mod edit -module %s && ", taskName)
				}

				commandSeq += `go mod tidy && go build -a -installsuffix cgo -o ` + taskName

				cmd := exec.Command("bash", "-c", commandSeq)
				cmd.Env = append(os.Environ(), []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64"}...)
				cmd.Dir = taskFolder
				_, err := cmd.Output()
				if err != nil {
					errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "cannot create validation task binary"})
					return errorDetails
				}

			} else {

				// applicationStructName := strcase.ToCamel(applicationVO.Meta.Name)
				// taskName := strcase.ToCamel("Validate" + applicationStructName)

				appModule := filepath.Join(appConnectionPath, folderName+".py")

				if utils.IsFileExist(appModule) {
					moduleByts, err := os.ReadFile(filepath.Join(appConnectionPath, folderName+".py"))
					if err != nil {
						errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "cannot read application module"})
						return errorDetails
					}

					appTaskModulePath := filepath.Join(taskFolder, folderName+".py")

					err = os.WriteFile(appTaskModulePath, moduleByts, os.ModePerm)
					if err != nil {
						errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "cannot write application module inside task"})
						return errorDetails
					}
					taskAppconnectionFolder := filepath.Join(taskFolder, filepath.Base(additionalInfo.PolicyCowConfig.PathConfiguration.AppConnectionPath))
					err = os.MkdirAll(taskAppconnectionFolder, os.ModePerm)
					if err != nil {
						errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "cannot create the appconnections folder inside task"})
						return errorDetails
					}
					opt := copy.Options{
						Skip: func(srcinfo os.FileInfo, src, dest string) (bool, error) {
							if src == appConnectionPath || (srcinfo.IsDir() && strings.HasPrefix(filepath.Base(src), "Validate")) {
								return true, nil
							}
							return false, nil
						},
					}
					err = copy.Copy(allAppsSorucePath, taskAppconnectionFolder, opt)
					if err != nil {
						errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "cannot copy the appconnections folder inside task"})
						return errorDetails
					}

					requirementsTxtPaths := []string{filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.AppConnectionPath, additionalInfo.Language, "requirements.txt"),
						filepath.Join(taskFolder, "requirements.txt")}

					mergeRequirements(requirementsTxtPaths, filepath.Join(taskFolder, "requirements.txt"))
					defer os.RemoveAll(taskAppconnectionFolder)
					defer os.Remove(appTaskModulePath)

				}

				// err = cp.Copy(filepath.Join(appConnectionPath, folderName+".py"), taskFolder+"/", cp.Options{
				// 	OnDirExists: func(src string, dst string) cp.DirExistsAction {
				// 		// Handle what to do when the destination directory exists (e.g., overwrite or skip)
				// 		return cp.Merge
				// 	},
				// })
				// if err != nil {
				// 	fmt.Println("error :", err)
				// 	errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "cannot copy application to task"})
				// 	return errorDetails
				// }

				errorCount := 0

			TarRetryLabel:

				err = utils.TARFiles(taskFolder, taskFolder, taskName)
				if err != nil {
					if errorCount < 3 {
						errorCount++
						s.Prefix = "Facing an issue while creating task as TAR file. Retrying...."
						time.Sleep(3 * time.Second)
						goto TarRetryLabel
					}

					errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "cannot create tar file for application validation task"})
					return errorDetails

				}

				binaryFileName = taskName + ".tar"
				workerNodeType = "py3"
			}

			s.Prefix = "Binary created for validation task ...."

			taskVO := &vo.CowTaskVO{CNAPIVersion: applicationVO.CowDeclarativeVO.APIVersion, CNTaskName: taskName,
				CNTaskAlias: taskName, CNTaskPurpose: applicationVO.Meta.LongDescription,
				DomianLevelAccess: true}

			taskVO.CNTaskVersion.UserVersion = applicationVO.Meta.Version

			taskResponse := &vo.CowTaskResponseVO{}

			taskURL := fmt.Sprintf("%s/v1/proxy/continube/api/task", apiEndpoint)

			resp, err := client.R().SetHeaders(headerMap).SetQueryParams(map[string]string{
				"op": "create",
			}).SetBody(taskVO).SetResult(taskResponse).SetError(&errorData).Post(taskURL)

			if err != nil || resp.StatusCode() != http.StatusOK || utils.IsEmpty(taskResponse.TaskGUID) {
				errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "cannot create task in rule engine"})
				return errorDetails
			}

			tagsUpdateVO := &vo.CowTaskTagsUpdateVO{
				Tags: struct {
					WorkernodeType []string `json:"workernodetype"`
					Type           []string `json:"type__"`
				}{
					WorkernodeType: []string{workerNodeType},
					Type:           []string{"validate"},
				},
				CNInputStrings: []struct {
					CNKey   string `json:"cnKey"`
					CNValue string `json:"cnValue"`
				}{
					{
						CNKey:   "TaskGUID",
						CNValue: taskResponse.TaskGUID,
					},
				},
			}

			resp, err = client.R().SetHeaders(headerMap).SetQueryParams(map[string]string{
				"op":     "update",
				"method": "tags",
			}).SetBody(tagsUpdateVO).SetResult(taskResponse).SetError(&errorData).Post(taskURL)

			if err != nil || resp.StatusCode() != http.StatusOK || utils.IsEmpty(taskResponse.TaskGUID) {
				errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "cannot update tags to the task in rule engine"})
				return errorDetails
			}

			taskBinaryUpdateURL := fmt.Sprintf("%s/update-binary", taskURL)

			resp, err = client.R().SetHeaders(headerMap).SetFormData(map[string]string{
				"taskGUID": taskResponse.TaskGUID,
			}).SetFile("binaryFile", filepath.Join(taskFolder, binaryFileName)).SetResult(taskResponse).SetError(&errorData).Post(taskBinaryUpdateURL)

			if err != nil || resp.StatusCode() != http.StatusOK || utils.IsEmpty(taskResponse.TaskGUID) {
				errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "cannot update binary to the task in rule engine"})
				return errorDetails
			}

		}

		s.Prefix = "Publishing the application ...."

		responseVO := &vo.CowResponseVO{}

		applicationVO.Spec.Validation.TaskName = taskName

		fileByts, err = yaml.Marshal(applicationVO)

		if err != nil {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "cannot marshal the application vo"})
			return errorDetails
		}

		err = utils.Validate.Struct(applicationVO)
		errorDetails = utils.GetValidationError(err)
		if len(errorDetails) > 0 {
			return errorDetails
		}

		request := client.R().SetHeaders(headerMap).SetHeader("Content-Type", "text/yaml").
			SetBody(fileByts).SetResult(responseVO).SetError(&errorData)

		if len(apps) == 0 {
			resp, err = request.Post(url)
		} else {
			url += "/" + apps[0].ID
			resp, err = request.Put(url)
		}

		if err != nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusCreated) || utils.IsEmpty(responseVO.ID) {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: "cannot publish the application"})
			return errorDetails
		}

		if len(errorData) > 4 {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: string(errorData)})
			return errorDetails
		}

		s.Prefix = "Successfully published."

	} else {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotFindApplication})
		return errorDetails
	}

	return nil
}

func CreateTaskInputYAMLWithAppConfig(folderPath string, applicationVO *vo.UserDefinedApplicationVO, credentialMap map[string]*credInfo) error {
	taskYaml := constants.TaskInputYAML

	var taskInput vo.TaskInput
	err := yaml.Unmarshal([]byte(taskYaml), &taskInput)
	if err != nil {
		return err
	}
	taskInput.UserObject.Name = applicationVO.Meta.Name

	userDefCreds := make([]*vo.UserDefinedCredentialVO, 0)
	for _, cred := range credentialMap {
		userDefCreds = append(userDefCreds, cred.Credential)
	}

	credentials := utils.GetCredentialYAMLObject(userDefCreds)
	byts, err := json.Marshal(credentials.UserDefinedCredentials)
	if err == nil {
		userDefinedCredentials := make(map[string]interface{}, 0)
		json.Unmarshal(byts, &userDefinedCredentials)
		taskInput.UserInputs["userDefinedCredentials"] = userDefinedCredentials
	}

	taskInput.UserInputs["appURL"] = applicationVO.Spec.URL
	taskInput.UserInputs["appPort"] = applicationVO.Spec.Port

	taskInputByts, err := yaml.Marshal(taskInput)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(folderPath, constants.TaskInputYAMLFile), taskInputByts, os.ModePerm)

}

func HandleDecalrativesCreation(applicationVO *vo.UserDefinedApplicationVO, additionalInfo *vo.AdditionalInfo) (map[string]*credInfo, []*vo.ErrorDetailVO) {
	err := utils.Validate.Struct(applicationVO)
	errorDetails := utils.GetValidationError(err)
	if len(errorDetails) > 0 {
		return nil, errorDetails
	}
	errorDetails = make([]*vo.ErrorDetailVO, 0)

	if additionalInfo == nil || additionalInfo.PolicyCowConfig == nil || additionalInfo.PolicyCowConfig.PathConfiguration == nil && utils.IsEmpty(additionalInfo.PolicyCowConfig.PathConfiguration.DeclarativePath) {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorFolderPathMissing})
		return nil, errorDetails
	}

	// if utils.IsEmpty(applicationVO.Meta.Version) {
	// 	applicationVO.Meta.Version = constants.VersionLatest
	// }

	// folderName := strings.ToLower(applicationVO.Meta.Name)
	folderName := applicationVO.Meta.Name

	credentialsPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.DeclarativePath, constants.UserDefinedCredentialsPath)

	appConnectionsPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.DeclarativePath, constants.UserDefinedApplicationPath)

	// folderPath := filepath.Join(appConnectionsPath, folderName, strings.ToLower(applicationVO.Meta.Version))

	folderPath := filepath.Join(appConnectionsPath, folderName)

	if utils.IsFolderExist(folderPath) && !applicationVO.IsVersionToBeOverride {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorApplicationAlreadyAvailable})
		return nil, errorDetails
	}

	if additionalInfo.ApplictionScopeConfigVO == nil || len(additionalInfo.ApplictionScopeConfigVO.FileData) < 2 {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorFileDataMissing})
		return nil, errorDetails
	}

	if utils.IsFolderNotExist(folderPath) {
		err = os.MkdirAll(folderPath, os.ModePerm)
		if err != nil {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotCreateApplicationFolder})
			return nil, errorDetails
		}
	}

	if len(errorDetails) > 0 {
		return nil, errorDetails
	}

	credentialMap := make(map[string]*credInfo, 0)

	validateAndGetCredentials := func(credential *vo.CowNamePointersVO) (*vo.UserDefinedCredentialVO, []*vo.ErrorDetailVO) {
		errorDetails = make([]*vo.ErrorDetailVO, 0)
		name, version := credential.Name, credential.Version
		if utils.IsEmpty(version) {
			version = constants.VersionDefault
		}

		if utils.IsEmpty(name) {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotFindCredential, Location: name})
			return nil, errorDetails
		}
		credPath := filepath.Join(credentialsPath, name, version, constants.YAMLTypeGenerated)
		if utils.IsFileNotExist(credPath) {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotFindCredential, Location: name})
			return nil, errorDetails
		}
		credentialByts, err := os.ReadFile(credPath)
		if err != nil {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotReadCredential, Location: name})
			return nil, errorDetails
		}
		credentialsVO := &vo.UserDefinedCredentialVO{}
		err = yaml.Unmarshal(credentialByts, credentialsVO)
		if err != nil {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotUnmarshalCredential, Location: name})
			return nil, errorDetails
		}

		// credentialMap[name] = &credInfo{Credential: credentialsVO, Repeated: repeated}
		return credentialsVO, errorDetails

	}

	if credentialTypes := applicationVO.Spec.CredentialTypes; len(credentialTypes) > 0 {
		// INFO : We need to override the attributes(if any) based on the declaration order

		for _, credential := range credentialTypes {
			credentialsVO, errorDetails := validateAndGetCredentials(&credential.CowNamePointersVO)
			if len(errorDetails) > 0 {
				return nil, errorDetails
			}
			credentialMap[credential.Name] = &credInfo{Credential: credentialsVO, Repeated: credential.Repeated}
		}

		if applicationVO.Spec.DefaultCredentialType != nil {

			if _, ok := credentialMap[applicationVO.Spec.DefaultCredentialType.Name]; !ok {
				credentialsVO, errorDetails := validateAndGetCredentials(applicationVO.Spec.DefaultCredentialType)
				if len(errorDetails) > 0 {
					return nil, errorDetails
				}
				credentialMap[applicationVO.Spec.DefaultCredentialType.Name] = &credInfo{Credential: credentialsVO}
			}

		} else {
			applicationVO.Spec.DefaultCredentialType = &applicationVO.Spec.CredentialTypes[0].CowNamePointersVO
		}

	}

	if len(credentialMap) == 0 {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCredentialMissing})
		return nil, errorDetails
	}

	if utils.IsEmpty(applicationVO.Spec.Validation.TaskName) {
		applicationStructName := strcase.ToCamel(applicationVO.Meta.Name)
		taskName := strcase.ToCamel("Validate" + applicationStructName)
		applicationVO.Spec.Validation.TaskName = taskName
	}

	fileByts, err := yaml.Marshal(applicationVO)

	if err != nil {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotUnmarshalApplication})
		return nil, errorDetails
	}

	errorDetails = utils.CreateDeclarativeFiles(additionalInfo.ApplictionScopeConfigVO.FileData, fileByts, folderPath)
	if len(errorDetails) > 0 {
		return nil, errorDetails
	}

	return credentialMap, nil
}

func mergeRequirements(filePaths []string, outputFilePath string) error {
	var lines []string

	for _, filePath := range filePaths {
		file, err := os.Open(filePath)
		if err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				lines = append(lines, strings.TrimSpace(scanner.Text()))
			}
			if err := scanner.Err(); err != nil {
				continue
			}
		}

	}

	if len(lines) == 0 {
		return nil
	}

	sort.Strings(lines)
	var uniqueLines []string
	for i := 0; i < len(lines); i++ {
		if i == 0 || lines[i] != lines[i-1] {
			uniqueLines = append(uniqueLines, lines[i])
		}
	}

	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	for _, line := range uniqueLines {
		fmt.Fprintln(outputFile, line)
	}

	return nil
}

func GetAvailableApplications(applicationName string, additionalInfo *vo.AdditionalInfo) (*vo.ApplicationValidatorRespVO, error) {
	respVO := &vo.ApplicationValidatorRespVO{}

	appClassPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationClassPath, fmt.Sprintf("%s.yaml", applicationName))
	applicationInfo, err := utils.GetApplicationWithCredential(appClassPath, additionalInfo.PolicyCowConfig.PathConfiguration.CredentialsPath)
	if err != nil {
		return nil, err
	}

	apps := make([]*vo.UserDefinedApplicationVO, 0)
	collection := &vo.Collection{}
	collection.Items = &apps
	errorData := json.RawMessage{}

	headerMap, err := utils.GetAuthHeader(additionalInfo)
	if err != nil {
		return nil, err
	}
	client := resty.New()
	apiEndpoint := utils.GetCowAPIEndpoint(additionalInfo)
	url := fmt.Sprintf("%s/v1/app-configs", apiEndpoint)

	resp, err := client.R().SetHeaders(headerMap).SetQueryParams(map[string]string{
		"name":    applicationInfo.App.Meta.Name,
		"version": applicationInfo.App.Meta.Version,
	}).SetResult(collection).SetError(&errorData).Get(url)

	if err != nil || resp.StatusCode() != http.StatusOK {
		return nil, errors.New("cannot fetch the applications")
	}

	if len(apps) > 0 {
		respVO.Valid = true
	}
	return respVO, nil

}
