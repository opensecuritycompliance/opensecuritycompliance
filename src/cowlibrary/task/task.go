package task

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"

	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/dmnlk/stringUtils"
	"github.com/iancoleman/strcase"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"gopkg.in/yaml.v2"

	"cowlibrary/constants"
	"cowlibrary/method"
	"cowlibrary/utils"
	"cowlibrary/vo"
)

func GetTaskFromLanguage(languageStr string) (Task, error) {
	var supportedLanguage constants.SupportedLanguage
	language, err := supportedLanguage.GetSupportedLanguage(languageStr)
	if err != nil {
		return nil, err
	}

	return GetTask(*language), nil

}

type Task interface {
	InitTask(taskName, path string, taskInput *vo.TaskInputVO, additionalInfo *vo.AdditionalInfo) error
	PrepareTask(taskPath string, additionalInfo *vo.AdditionalInfo) error
	CreateTaskWithYAML(yamlFilePath, rulePath, catalogFile string, additionalInfo *vo.AdditionalInfo) error
	CreateTaskWithYAMLStruct(taskFlow vo.TaskFlow, rulePath string, additionalInfo *vo.AdditionalInfo) error
	CreateTaskStructs(taskDetails *vo.TaskDetails, inputs, outputs []vo.PolicyCowIOInfo, additionalInfo *vo.AdditionalInfo) error
	GenerateInputOutputStructs(inputs, outputs []vo.PolicyCowIOInfo) (string, string)
	GenerateTaskCode(taskName string, taskDetails *vo.TaskDetails, taskFlow vo.TaskFlow) error
}

type GoTask struct {
}

func GetTask(language constants.SupportedLanguage) Task {
	switch language {
	case constants.SupportedLanguagePython:
		return &PythonTask{}
	default:
		return &GoTask{}
	}
}

func (task *GoTask) InitTask(taskName, tasksPath string, taskInput *vo.TaskInputVO, additionalInfo *vo.AdditionalInfo) error {

	taskName = strcase.ToCamel(taskName)
	taskPath := filepath.Join(tasksPath, taskName)

	if utils.IsFolderNotExist(taskPath) {
		if err := os.MkdirAll(taskPath, os.ModePerm); err != nil {
			return err
		}
	}
	// make sure file exists
	ruleAppTags := make(map[string][]string)
	if utils.IsFileExist(filepath.Join(additionalInfo.Path, constants.TaskInputYAMLFile)) {
		ruleInputYAMLBytes, err := os.ReadFile(filepath.Join(additionalInfo.Path, constants.TaskInputYAMLFile))
		if err != nil {
			return fmt.Errorf("failed to read rule inputs.yaml: %s", err)
		}
		var taskInput vo.TaskInputV2
		err = yaml.Unmarshal(ruleInputYAMLBytes, &taskInput)
		if err != nil {
			return fmt.Errorf("error unmarshalling taskInput.yaml: %s", err)
		}
		ruleYAMLBytes, err := os.ReadFile(filepath.Join(additionalInfo.Path, constants.RuleYamlFile))
		if err != nil {
			return fmt.Errorf("failed to read rule.yaml: %s", err)
		}
		var rule vo.RuleYAMLVO
		err = yaml.Unmarshal(ruleYAMLBytes, &rule)
		if err != nil {
			return fmt.Errorf("error unmarshalling rule.yaml: %s", err)
		}
		for _, taskInfo := range rule.Spec.Tasks {
			if taskInfo.Name == taskName {
				if taskInfo.AppTags != nil {
					var selectedApp *vo.AppAbstract
					for _, app := range taskInput.UserObject.Apps {
						if app != nil && reflect.DeepEqual(app.AppTags, taskInfo.AppTags) {
							ruleAppTags = taskInfo.AppTags
							selectedApp = app
							break
						}
					}
					taskInput.UserObject.App = selectedApp
					taskInput.UserObject.Apps = nil
				} else {
					taskInput.UserObject = nil
				}
				break
			}
		}
		updatedTaskInputYAML, err := yaml.Marshal(&taskInput)
		if err != nil {
			return fmt.Errorf("error marshalling updated taskInput.yaml: %w", err)
		}
		err = os.WriteFile(filepath.Join(taskPath, constants.TaskInputYAMLFile), updatedTaskInputYAML, os.ModePerm)
		if err != nil {
			return fmt.Errorf("error writing updated taskInput.yaml: %w", err)
		}

	}

	srcTaskName := path.Base(taskPath)
	var re = regexp.MustCompile(`Task([0-9]*[_])`)
	srcTaskName = re.ReplaceAllString(srcTaskName, ``)

	mainFile := strings.ReplaceAll(constants.TaskMain, "{{TaskName}}", srcTaskName)
	if err := os.WriteFile(filepath.Join(taskPath, constants.AutoGeneratedFilePrefix+"main.go"), []byte(mainFile), os.ModePerm); err != nil {
		return err
	}
	serverStructFile := constants.TaskServerStructWithPackage
	var importPackage string
	var appClassName string
	var validationMethod string
	classAvailable := false

	if additionalInfo.ApplicationInfo != nil {
		for _, appInfo := range additionalInfo.ApplicationInfo {
			if appInfo != nil && appInfo.App != nil && appInfo.App.Meta != nil && ruleAppTags != nil {
				if reflect.DeepEqual(appInfo.App.AppTags, ruleAppTags) {
					appClassName = appInfo.App.Meta.Name

					validationMethod = fmt.Sprintf(`
	// You can use the ValidateAttributes() function to validate the attributes of %s Credentials
	`, appInfo.App.Meta.Name)
					if utils.IsNotEmpty(appClassName) {
						packageName := strings.ToLower(appClassName)

						if utils.IsFolderExist(filepath.Join(utils.GetApplicationTypesPathWithLanguage(additionalInfo, constants.SupportedLanguageGo.String()), packageName)) {
							classAvailable = true
							importPackage = strings.ToLower(appClassName) + ` "applicationtypes/` + packageName + `"`
							serverStructFile = strings.ReplaceAll(serverStructFile, "{{import()}}", importPackage)
							userDefinedCredential := strings.ToLower(appClassName) + `.UserDefinedCredentials`
							serverStructFile = strings.ReplaceAll(serverStructFile, "{{UserDefinedCredentials}}", userDefinedCredential)
						}

						for _, cred := range appInfo.Credential {
							credentialName := strcase.ToCamel(cred.Meta.Name)
							validationCode := fmt.Sprintf(`
		// Validate attributes for %s
		// %s := inst.SystemInputs.UserObject.App.UserDefinedCredentials.%s
		// validationResult := %s.ValidateAttributes()
				`, cred.Meta.Name, credentialName, credentialName, credentialName)

							validationMethod += validationCode
						}
					}
				}
			}
		}
	}

	if !classAvailable {
		serverStructFile = strings.ReplaceAll(serverStructFile, "{{UserDefinedCredentials}}", "interface{}")
		serverStructFile = strings.ReplaceAll(serverStructFile, "{{import()}}", "")
	}

	if err := os.WriteFile(filepath.Join(taskPath, constants.AutoGeneratedFilePrefix+"serverStructs.go"), []byte(serverStructFile), os.ModePerm); err != nil {
		return err
	}

	// if err := os.WriteFile(filepath.Join(taskPath, constants.AutoGeneratedFilePrefix+"file_store.go"), []byte(constants.FileStore), os.ModePerm); err != nil {
	// 	return err
	// }

	if err := os.WriteFile(taskPath+string(os.PathSeparator)+"task_service_structs.go", []byte(constants.TaskServiceStructs), os.ModePerm); err != nil {
		return err
	}
	taskServiceFile := strings.ReplaceAll(constants.TaskService, "{{TaskName}}", taskName)
	taskServiceFile = strings.ReplaceAll(taskServiceFile, "{{ValidationMethod}}", validationMethod)
	if err := os.WriteFile(taskPath+string(os.PathSeparator)+"task_service.go", []byte(taskServiceFile), os.ModePerm); err != nil {
		return err
	}

	metaYAMLFile := strings.ReplaceAll(constants.MetaYAML, "{{TaskName}}", taskName)
	metaYAMLFile = strings.ReplaceAll(metaYAMLFile, "{{CreatedDate}}", time.Now().Format("02/01/2006"))
	metaYAMLFile = strings.ReplaceAll(metaYAMLFile, "{{Type}}", "go")

	if err := os.WriteFile(filepath.Join(taskPath, "__meta.yaml"), []byte(metaYAMLFile), os.ModePerm); err != nil {
		return err
	}

	// InitializeGoModFile
	err := utils.InitializeGoModFile(taskPath, taskName)

	// if additionalInfo.IsTasksToBePrepare {
	// 	task.PrepareTask(taskPath, additionalInfo)
	// }

	return err
}

// rule's input.yaml builder
func GenerateTaskYAML(taskPath string, taskName string, additionalInfo *vo.AdditionalInfo) (string, error) {
	taskYaml := constants.TaskInputYAML
	var taskInput vo.TaskInputV2

	err := yaml.Unmarshal([]byte(taskYaml), &taskInput)
	if err != nil {
		fmt.Printf("Error in unmarshalling task input yaml,error: %s", err)
	}

	if len(additionalInfo.ApplicationInfo) > 0 {
		for _, appInfo := range additionalInfo.ApplicationInfo {
			if appInfo != nil {
				isAppFound := false
				for _, existingApp := range taskInput.UserObject.Apps {
					if existingApp.ApplicationName == appInfo.App.Meta.Name && reflect.DeepEqual(existingApp.AppTags, appInfo.App.AppTags) {
						isAppFound = true
						break
					}
				}
				if !isAppFound {
					appAbstract := &vo.AppAbstract{}
					appAbstract.ApplicationName = appInfo.App.Meta.Name
					appAbstract.ApplicationURL = appInfo.App.Spec.URL
					appAbstract.ApplicationPort = strconv.Itoa(appInfo.App.Spec.Port)
					appAbstract.AppTags = appInfo.App.AppTags
					credentials := utils.GetCredentialYAMLObjectV2(appInfo.Credential)
					appAbstract.UserDefinedCredentials = credentials.UserDefinedCredentials

					if additionalInfo.PrimaryApplicationInfo != nil {
						taskInput.UserObject.Apps = append(taskInput.UserObject.Apps, appAbstract)
					} else {
						taskInput.UserObject.App = appAbstract
					}

					if appInfo.LinkedApplications != nil && len(appInfo.LinkedApplications) > 0 {
						AddLinkedApplicationsInAppAbstract(appInfo.LinkedApplications, appAbstract)
					}
				}
			}
		}
	}

	if additionalInfo.RuleYAMLVO != nil && additionalInfo.RuleYAMLVO.Spec != nil {
		taskInput.UserInputs = additionalInfo.RuleYAMLVO.Spec.Input
	}

	taskInput.FromDate_ = "{{FROM_DATE}}"
	taskInput.ToDate_ = "{{FROM_DATE}}"

	taskInputByts, err := yaml.Marshal(taskInput)
	if err != nil {
		fmt.Printf("Error in marshalling task, error : %s", err)
	}

	dateValue := strings.ReplaceAll(string(taskInputByts), "'{{FROM_DATE}}'", time.Now().Format(constants.DateTimeFormatDefault))
	dateValue = strings.ReplaceAll(dateValue, "\"{{FROM_DATE}}\"", time.Now().Format(constants.DateTimeFormatDefault))
	dateValue = strings.ReplaceAll(dateValue, "{{FROM_DATE}}", time.Now().Format(constants.DateTimeFormatDefault))

	taskYAMLPath := filepath.Join(taskPath, "inputs.yaml")

	err = os.WriteFile(taskYAMLPath, []byte(dateValue), os.ModePerm)
	if err != nil {
		return "", err
	}
	return taskYAMLPath, nil
}

func AddLinkedApplicationsInAppAbstract(linkedApplications []*vo.ApplicationInfoVO, parentAppAbstract *vo.AppAbstract) {
	linkedApplicationsMap := make(map[string][]*vo.AppAbstract)
	var getLinkedApplicationsDetails func(linkedApplications []*vo.ApplicationInfoVO, parentLinkedApplicationMap map[string][]*vo.AppAbstract)
	getLinkedApplicationsDetails = func(linkedApplications []*vo.ApplicationInfoVO, parentLinkedApplicationMap map[string][]*vo.AppAbstract) {
		for _, linkedApp := range linkedApplications {
			appAbstractArray := make([]*vo.AppAbstract, 0)
			appAbstract := &vo.AppAbstract{}
			appAbstract.ApplicationName = linkedApp.App.Meta.Name
			appAbstract.ApplicationURL = linkedApp.App.Spec.URL
			appAbstract.ApplicationPort = strconv.Itoa(linkedApp.App.Spec.Port)
			credentials := utils.GetCredentialYAMLObjectV2(linkedApp.Credential)
			appAbstract.UserDefinedCredentials = credentials.UserDefinedCredentials
			appAbstract.LinkedApplications = make(map[string][]*vo.AppAbstract)
			if linkedApp.LinkedApplications != nil && len(linkedApp.LinkedApplications) > 0 {
				getLinkedApplicationsDetails(linkedApp.LinkedApplications, appAbstract.LinkedApplications)
			}
			appAbstractArray = append(appAbstractArray, appAbstract)
			parentLinkedApplicationMap[linkedApp.App.Meta.Name] = appAbstractArray
		}
	}
	getLinkedApplicationsDetails(linkedApplications, linkedApplicationsMap)
	parentAppAbstract.LinkedApplications = linkedApplicationsMap
}

func CreateJsonFiles(taskPath, taskName string) error {

	if err := os.MkdirAll(taskPath+string(os.PathSeparator)+"files", os.ModePerm); err != nil {
		return err
	}

	if err := os.WriteFile(taskPath+string(os.PathSeparator)+"files"+string(os.PathSeparator)+"MetaDataValue.json", []byte(constants.MetaDataValueJSON), os.ModePerm); err != nil {
		return err
	}

	if err := os.WriteFile(taskPath+string(os.PathSeparator)+"files"+string(os.PathSeparator)+"TaskInputValue.json", []byte(constants.TaskInputValueJSON), os.ModePerm); err != nil {
		return err
	}

	if err := os.WriteFile(taskPath+string(os.PathSeparator)+"files"+string(os.PathSeparator)+"UserObjectAppValue.json", []byte(constants.UserObjectAppValueJSON), os.ModePerm); err != nil {
		return err
	}

	if err := os.WriteFile(taskPath+string(os.PathSeparator)+"files"+string(os.PathSeparator)+"UserObjectServerValue.json", []byte(constants.UserObjectServerValueJSON), os.ModePerm); err != nil {
		return err
	}

	return nil
}

func (task *GoTask) PrepareTask(taskPath string, additionalInfo *vo.AdditionalInfo) error {
	if stringUtils.IsEmpty(taskPath) {
		return errors.New("task path cannot be empty")
	}

	if _, err := os.Stat(taskPath); os.IsNotExist(err) {
		return errors.New("not a valid path")
	}

	// if err := os.MkdirAll(filepath.Join(taskPath, "flow"), os.ModePerm); err != nil {
	// 	return err
	// }
	srcTaskName := path.Base(taskPath)
	var re = regexp.MustCompile(`Task([0-9]*[_])`)
	srcTaskName = re.ReplaceAllString(srcTaskName, ``)

	mainFile := strings.ReplaceAll(constants.TaskMain, "{{TaskName}}", srcTaskName)

	if err := os.WriteFile(filepath.Join(taskPath, constants.AutoGeneratedFilePrefix+"main.go"), []byte(mainFile), os.ModePerm); err != nil {
		return err
	}
	serverStructFile := strings.ReplaceAll(constants.TaskServerStructWithPackage, "{{UserDefinedCredentials}}", "interface{}")
	serverStructFile = strings.ReplaceAll(serverStructFile, "{{import()}}", "")
	if err := os.WriteFile(filepath.Join(taskPath, constants.AutoGeneratedFilePrefix+"serverStructs.go"), []byte(serverStructFile), os.ModePerm); err != nil {
		return err
	}

	// if err := os.WriteFile(filepath.Join(taskPath, constants.AutoGeneratedFilePrefix+"file_store.go"), []byte(constants.FileStore), os.ModePerm); err != nil {
	// 	return err
	// }

	return nil
}

func (task *GoTask) CreateTaskWithYAML(yamlFilePath, rulePath, catalogFile string, additionalInfo *vo.AdditionalInfo) error {

	taskFlow, err := GetTaskFlowFromFilePath(yamlFilePath)
	if err != nil {
		return err
	}

	s := spinner.New(spinner.CharSets[43], 100*time.Millisecond)
	s.Start()

	defer s.Stop()

	return task.CreateTaskWithYAMLStruct(*taskFlow, rulePath, additionalInfo)
}

func GetTaskFlowFromFilePath(yamlFilePath string) (*vo.TaskFlow, error) {
	yamlFile, err := os.ReadFile(yamlFilePath)
	if err != nil {
		return nil, err
	}

	var taskFlow vo.TaskFlow
	err = yaml.Unmarshal(yamlFile, &taskFlow)
	if err != nil {
		return nil, err
	}

	return &taskFlow, nil

}

func (task *GoTask) CreateTaskWithYAMLStruct(taskFlow vo.TaskFlow, rulePath string, additionalInfo *vo.AdditionalInfo) error {
	err := task.InitTask(taskFlow.Metadata.Name, rulePath, &vo.TaskInputVO{}, additionalInfo)

	if err != nil {
		return err
	}

	// TODO : Check whether we need to test the rule path
	taskDetails, err := utils.GetTaskDetails(rulePath, taskFlow.Metadata.Name, additionalInfo)
	if err != nil {
		return err
	}

	err = task.PrepareTask(taskDetails.TaskPath, additionalInfo)

	if err != nil {
		return err
	}

	err = task.CreateTaskStructs(taskDetails, taskFlow.Spec.TaskInputs, taskFlow.Spec.TaskOutputs, additionalInfo)

	if err != nil {
		return err
	}

	err = task.GenerateTaskCode(taskFlow.Metadata.Name, taskDetails, taskFlow)
	if err != nil {
		return fmt.Errorf("error Creating Folder Structure: %s", err.Error())
	}

	if err := os.Chdir(taskDetails.TaskPath); err != nil {
		return fmt.Errorf("error Changing Directory: %s", err.Error())

	}
	commands := []string{
		"pwd",
	}
	modExist := true
	if _, err := os.Stat("go.mod"); os.IsNotExist(err) {
		modExist = false
	}
	if !modExist {
		commands = append(commands, "go mod init tmp")
	} else {
		commands = append(commands, "cp go.mod go.mod.bk")
	}
	_, err = runCmds(commands)
	if err != nil {
		return fmt.Errorf("error Running Commands: %s", err.Error())
	}

	fileContent, err := os.ReadFile("go.mod")
	if err != nil {
		return fmt.Errorf("error Writing to File: %s", err.Error())
	}

	lines := strings.Split(string(fileContent), "\n")

	fileContent = []byte(strings.Join(lines, "\n"))
	err = os.WriteFile("go.mod", fileContent, 0644)
	if err != nil {
		return err
	}
	commands = []string{
		"cat go.mod",
		"go mod tidy",
		"cat go.mod",
		"go build -buildvcs=false -o tmp",
		"rm tmp",
	}

	_, err = runCmds(commands)
	if err != nil {
		return err
	}

	return nil
}

func (task *GoTask) CreateTaskStructs(taskDetails *vo.TaskDetails, inputs, outputs []vo.PolicyCowIOInfo, additionalInfo *vo.AdditionalInfo) error {

	replaceinputstring, replaceoutputstring := task.GenerateInputOutputStructs(inputs, outputs)

	deststring := strings.ReplaceAll(constants.TaskServiceStructs_V2, "{{replace_input_fields}}", replaceinputstring)

	deststring = strings.ReplaceAll(string(deststring), "{{replace_output_fields}}", replaceoutputstring)

	if err := os.WriteFile(taskDetails.TaskPath+string(os.PathSeparator)+"task_service_structs.go", []byte(deststring), os.ModePerm); err != nil {
		return err
	}

	return nil
}

func (task *GoTask) GenerateInputOutputStructs(inputs, outputs []vo.PolicyCowIOInfo) (string, string) {

	var inputString, outputString string

	for _, variable := range inputs {
		inputString = inputString + variable.Name + " string \n"

	}

	for _, variable := range outputs {
		outputString = outputString + variable.Name + " string \n"

	}
	return inputString, outputString

}

func (task *GoTask) GenerateTaskCode(taskName string, taskDetails *vo.TaskDetails, taskFlow vo.TaskFlow) error {

	taskName = strcase.ToCamel(taskName)

	destString := strings.ReplaceAll(constants.TaskService_V2, "{{replace_method_name}}", taskName)

	codeCatalog, err := method.GetAvailableMethods(taskFlow.Spec.MethodCatalogFilePath)
	if err != nil {
		return err
	}

	// TODO : Fill Default Implementation for missing methods

	var importList []string
	var methodCode string
	for _, method := range taskFlow.Spec.Methods {
		var receivingString string
		for _, code := range codeCatalog {
			if code.Method == method.Name {

				importList = append(importList, code.Imports...)
				methodCode = methodCode + code.MethodCode + "\n"

				receivingString = receivingString + code.MethodCall + "\n"

			}

		}

		destString = strings.ReplaceAll(destString, "{{replace_final_code}}", receivingString+"{{replace_final_code}}\n")

	}
	imports := removeDuplicateStr(importList)
	var destImport string
	for _, item := range imports {
		destImport = destImport + "\"" + item + "\"\n"
	}

	destString = strings.ReplaceAll(destString, "{{replace_final_code}}", "\n")
	destString = strings.ReplaceAll(destString, "{{replace_with_imports}}", destImport)
	destString = strings.ReplaceAll(destString, "{{replace_methods}}", methodCode)

	err = os.WriteFile(""+taskDetails.TaskPath+"/task_service.go", []byte(destString), 0755)

	if err != nil {
		return err
	}
	return nil

}

func runCmds(commands []string) (string, error) {
	for _, command := range commands {
		_, err := TokenizeAndRun(command)
		if err != nil {
			return command + " failed", err
		}
	}
	return "", nil
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

// TokenizeAndRun takes the cmdstr and runs it as a shell command and return output
func TokenizeAndRun(cmdStr string) ([]byte, error) {
	return TokenizeAndRunV2(cmdStr, "")
}

// TokenizeAndRunV2 takes the cmdstr and dir and runs it as a shell command and return output
func TokenizeAndRunV2(cmdStr, dir string) ([]byte, error) {
	if cmdStr == ":" {
		return nil, nil
	}
	parts := strings.Fields(cmdStr)
	if len(parts) >= 1 {
		head := parts[0]
		args := []string{}
		if len(parts) > 1 {
			args = parts[1:len(parts)]
		}
		cmd := exec.Command(head, args...)
		var stdoutBuf, stderrBuf bytes.Buffer
		cmd.Stdout = &stdoutBuf
		cmd.Stderr = &stderrBuf
		if dir != "" {
			cmd.Dir = dir
		}
		err := cmd.Run()
		stdout := stdoutBuf.Bytes()
		stderr := stderrBuf.Bytes()
		if err != nil {
			return stdout, errors.Wrap(err, string(stderr))
		}
		errResp := gjson.GetBytes(stdout, "error")
		if errResp.Exists() && len(errResp.Raw) > 0 {
			return stdout, errors.New(errResp.String())
		}
		return stdout, nil
	}
	return nil, errors.New("'" + cmdStr + "': the cmdStr is invalid, it has no head or args")
}
