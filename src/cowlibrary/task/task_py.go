package task

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/iancoleman/strcase"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	"cowlibrary/constants"
	"cowlibrary/method"
	"cowlibrary/utils"
	"cowlibrary/vo"
)

type PythonTask struct {
}

func (task *PythonTask) InitTask(taskName, tasksPath string, taskInputVO *vo.TaskInputVO, additionalInfo *vo.AdditionalInfo) error {
	taskPath := filepath.Join(tasksPath, taskName)
	taskDetails := &vo.TaskDetails{TaskPath: taskPath}

	if _, err := os.Stat(taskDetails.TaskPath); os.IsNotExist(err) {
		if err := os.MkdirAll(taskDetails.TaskPath, os.ModePerm); err != nil {
			return err
		}
	}
	ruleAppTags := make(map[string][]string)

	// make sure file exists
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
							selectedApp = app
							ruleAppTags = taskInfo.AppTags
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

	// if err := CreateJsonFiles(taskDetails.TaskPath, taskName); err != nil {
	// 	return err
	// }

	taskServiceFile := strings.ReplaceAll(constants.TaskPy, "{{replace_method_name}}", taskDetails.SrcTaskName)

	classAvailable := false
	var validationMethod string
	if len(additionalInfo.ApplicationInfo) > 0 {
		for _, appInfo := range additionalInfo.ApplicationInfo {
			if appInfo != nil && appInfo.App != nil && appInfo.App.Meta != nil && ruleAppTags != nil {
				if reflect.DeepEqual(appInfo.App.AppTags, ruleAppTags) {
					appClassName := appInfo.App.Meta.Name
					if utils.IsNotEmpty(appClassName) {
						packageName := strings.ToLower(appClassName)
						if utils.IsFolderExist(filepath.Join(utils.GetAppConnectionsPathWithLanguage(additionalInfo, constants.SupportedLanguageGo.String()), packageName)) {
							classAvailable = true
							importPackage := "#As per the selected app, we're importing the app package \nfrom appconnections." + strings.ToLower(appClassName) + " import " + strings.ToLower(appClassName)
							taskServiceFile = strings.ReplaceAll(taskServiceFile, "{{replace_with_imports}}", importPackage)
							taskServiceFile = strings.ReplaceAll(taskServiceFile, "{{APPLICATION_STRUCT_NAME}}", strcase.ToCamel(appClassName))
							taskServiceFile = strings.ReplaceAll(taskServiceFile, "{{APPLICATION_PACKAGE_NAME}}", strings.ToLower(appClassName))
						}
						validationMethod = fmt.Sprintf(`
		# You can use validate_attributes function to validate the attributes of %s Credentials`, appClassName)
						for _, cred := range appInfo.Credential {
							credentialName := strcase.ToSnake(cred.Meta.Name)
							validationCode := fmt.Sprintf(`
		# Validate attributes for %s
		# %s = app.user_defined_credentials.%s
		# if isinstance(%s, %s.%s):
		# 	validation_result = %s.validate_attributes()`, cred.Meta.Name, credentialName, credentialName, credentialName, packageName, cred.Meta.Name, credentialName)

							validationMethod += validationCode
						}
					}
				}
			}
		}

	}
	taskServiceFile = strings.ReplaceAll(taskServiceFile, "{{VALIDATION_METHOD}}", validationMethod)

	if !classAvailable {
		taskServiceFile = strings.ReplaceAll(taskServiceFile, "{{replace_with_imports}}", "")
	}

	taskServiceFile = strings.ReplaceAll(taskServiceFile, "{{replace_final_code}}", "")

	if taskInputVO != nil {
		if taskInputVO.IsSQLRule {
			taskServiceFile = strings.ReplaceAll(constants.SQLRule_Task, "{{replace_method_name}}", taskDetails.SrcTaskName)
			taskServiceFile = strings.ReplaceAll(taskServiceFile, "{{task_folder_name}}", taskDetails.TaskPath)
		}

		if len(taskInputVO.SupportFilesToCreate) > 0 {
			for _, fileToCreate := range taskInputVO.SupportFilesToCreate {
				if utils.IsNotEmpty(fileToCreate.FileName) && len(fileToCreate.FileData) > 2 {
					if err := os.WriteFile(taskDetails.TaskPath+string(os.PathSeparator)+fileToCreate.FileName, fileToCreate.FileData, os.ModePerm); err != nil {
						return err
					}
				}
			}
		}
	}

	taskServiceFile = strings.ReplaceAll(taskServiceFile, "{{replace_methods}}", "")

	if err := os.WriteFile(taskDetails.TaskPath+string(os.PathSeparator)+"task.py", []byte(taskServiceFile), os.ModePerm); err != nil {
		return err
	}

	if additionalInfo.IsTasksToBePrepare {
		task.PrepareTask(taskDetails.TaskPath, additionalInfo)
	}

	metaYAMLFile := strings.ReplaceAll(constants.MetaYAML, "{{TaskName}}", taskName)
	metaYAMLFile = strings.ReplaceAll(metaYAMLFile, "{{CreatedDate}}", time.Now().Format("02/01/2006"))
	metaYAMLFile = strings.ReplaceAll(metaYAMLFile, "{{Type}}", "python")

	if err := os.WriteFile(filepath.Join(taskPath, "__meta.yaml"), []byte(metaYAMLFile), os.ModePerm); err != nil {
		return err
	}

	return nil
}

func (task *PythonTask) PrepareTask(taskPath string, additionalInfo *vo.AdditionalInfo) error {
	if utils.IsEmpty(taskPath) {
		return errors.New("task path cannot be empty")
	}

	if _, err := os.Stat(taskPath); os.IsNotExist(err) {
		return errors.New("not a valid path")
	}

	if strings.HasSuffix(taskPath, "/") {
		taskPath = taskPath[:len(taskPath)-1]
	}

	srcTaskName := path.Base(taskPath)
	var re = regexp.MustCompile(`Task([0-9]*[_])`)
	srcTaskName = re.ReplaceAllString(srcTaskName, ``)

	mainFile := strings.ReplaceAll(constants.TaskHelperPy, "{{task_folder_name}}", taskPath)
	mainFile = strings.ReplaceAll(mainFile, "{{task_name}}", srcTaskName)

	if err := os.WriteFile(taskPath+string(os.PathSeparator)+constants.AutoGeneratedFilePrefix+"main.py", []byte(mainFile), os.ModePerm); err != nil {
		return err
	}

	os.WriteFile(filepath.Join(taskPath, "requirements.txt"), []byte("PyYAML"), os.ModePerm)

	return nil
}

func (task *PythonTask) CreateTaskWithYAML(yamlFilePath, rulePath, catalogFile string, additionalInfo *vo.AdditionalInfo) error {

	taskFlow, err := GetTaskFlowFromFilePath(yamlFilePath)
	if err != nil {
		return err
	}

	s := spinner.New(spinner.CharSets[43], 100*time.Millisecond)
	s.Start()

	defer s.Stop()

	return task.CreateTaskWithYAMLStruct(*taskFlow, rulePath, additionalInfo)
}

func (task *PythonTask) CreateTaskWithYAMLStruct(taskFlow vo.TaskFlow, rulePath string, additionalInfo *vo.AdditionalInfo) error {
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

	err = task.GenerateTaskCode(taskFlow.Metadata.Name, taskDetails, taskFlow)
	if err != nil {
		return fmt.Errorf("error Creating Folder Structure: %s", err.Error())
	}

	if err := os.Chdir(taskDetails.TaskPath); err != nil {
		return fmt.Errorf("error Changing Directory: %s", err.Error())

	}

	// TODO : Implement auto import packages or install

	return nil
}

func (task *PythonTask) CreateTaskStructs(taskDetails *vo.TaskDetails, inputs, outputs []vo.PolicyCowIOInfo, additionalInfo *vo.AdditionalInfo) error {

	return nil
}

func (task *PythonTask) GenerateInputOutputStructs(inputs, outputs []vo.PolicyCowIOInfo) (string, string) {

	var inputString, outputString string

	for _, variable := range inputs {
		inputString = inputString + variable.Name + " string \n"

	}

	for _, variable := range outputs {
		outputString = outputString + variable.Name + " string \n"

	}
	return inputString, outputString

}

func (task *PythonTask) GenerateTaskCode(taskName string, taskDetails *vo.TaskDetails, taskFlow vo.TaskFlow) error {

	taskName = strcase.ToCamel(taskName)

	destString := strings.ReplaceAll(constants.TaskPy, "{{replace_method_name}}", taskName)

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

	err = os.WriteFile(""+taskDetails.TaskPath+"/task.py", []byte(destString), 0755)

	if err != nil {
		return err
	}
	return nil

}
