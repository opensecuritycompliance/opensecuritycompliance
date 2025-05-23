package applications

import (
	"context"
	"cowlibrary/constants"
	"cowlibrary/task"
	"cowlibrary/utils"
	"cowlibrary/vo"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/iancoleman/strcase"
)

type PythonApplicationHandler struct {
	Context context.Context
}

func (applicationHandler *PythonApplicationHandler) Create(applicationVO *vo.UserDefinedApplicationVO, additionalInfo *vo.AdditionalInfo) []*vo.ErrorDetailVO {

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

func (applicationHandler *PythonApplicationHandler) GenerateApplicationStruct(applicationVO *vo.UserDefinedApplicationVO, credentialsMap map[string]*credInfo, additionalInfo *vo.AdditionalInfo) error {

	credentialDefs := make([]string, 0)

	selfParams := make([]string, 0)
	fromDict := make([]string, 0)
	toDict := make([]string, 0)
	paramNames := make([]string, 0)
	defaultValues := make([]string, 0)
	selfAttributes := make([]string, 0)
	initHelperMethods := make([]string, 0)

	validateMethod := `
	def validate_attributes(self) -> str:
		emptyAttrs = []`

	linkedAppFromDict := make([]string, 0)
	linkedAppToDict := make([]string, 0)
	linkedAppInitHelperMethods := make([]string, 0)
	linkedAppDefaultValues := make([]string, 0)
	linkedAppParamNames := make([]string, 0)
	linkedSelfParams := make([]string, 0)
	linkedApplicationAvailable := false
	linkedAppsImports := make([]string, 0)
	linkedAppsClassVariables := make([]string, 0)

	for _, app := range applicationVO.Spec.LinkableApplicationClasses {
		linkedApplicationAvailable = true
		paramName := strcase.ToSnake(app.Name) + "_app"
		appNameSmall := strings.ToLower(app.Name)
		linkedAppParamNames = append(linkedAppParamNames, paramName)
		importStatement := fmt.Sprintf("from applicationtypes.%s import %s", appNameSmall, appNameSmall)
		classVariables := fmt.Sprintf("\t%s: List[%s.%s]", paramName, appNameSmall, app.Name)

		linkedAppsImports = append(linkedAppsImports, importStatement)
		linkedAppsClassVariables = append(linkedAppsClassVariables, classVariables)

		defaultValue := `[]`
		fromDictStr := "\t\t\t"
		toDictStr := "\t\t"

		fromDictStr += paramName + `=[` + appNameSmall + `.` + app.Name + `.from_dict(item) for item in obj.get("` + app.Name + `",[])]`
		toDictStr += `result["` + app.Name + `"]=[item.to_dict() for item in self.` + paramName + `]`

		linkedAppInitHelperMethods = append(linkedAppInitHelperMethods, "\t\tself."+paramName+" = "+paramName)

		paramStruct := fmt.Sprintf("\t%s: List[%s.%s]", paramName, appNameSmall, app.Name)
		linkedSelfParams = append(linkedSelfParams, paramStruct)

		linkedAppToDict = append(linkedAppToDict, toDictStr)
		linkedAppDefaultValues = append(linkedAppDefaultValues, defaultValue)
		linkedAppFromDict = append(linkedAppFromDict, fromDictStr)
	}
	for credentialName, credential := range credentialsMap {
		paramName := strcase.ToSnake(credentialName)
		credentialName = strcase.ToCamel(credentialName)
		paramNames = append(paramNames, paramName)
		defaultValue := `None`
		paramStruct := paramName + `:	`
		// attributeType := "str"
		fromDictStr := "\t\t\t"
		toDictStr := "\t\t"

		// fromDictStr = "            "
		// toDictStr = "        "

		fromDictStr += paramName + ` = 	` + credentialName + `.from_dict(obj.get("` + credentialName + `",None)) `
		toDictStr += `result["` + credentialName + `"]=self.` + paramName + `.to_dict()`

		// fromDictStr = "            "
		// toDictStr = "        "

		// fromDictStr = ""
		// toDictStr = ""

		initHelperMethods = append(initHelperMethods, "\t\tself."+paramName+" = "+paramName)
		// initHelperMethods = append(initHelperMethods, "self."+paramName+" = "+paramName)
		// initHelperMethods = append(initHelperMethods, "        self."+paramName+" = "+paramName)

		toDict = append(toDict, toDictStr)
		defaultValues = append(defaultValues, defaultValue)
		fromDict = append(fromDict, fromDictStr)

		attributeType := credentialName
		if credential.Repeated {
			attributeType = `List[` + credentialName + `]`
		}

		paramStruct += attributeType

		selfParams = append(selfParams, paramStruct)

		// selfAttributes = append(selfAttributes, ""+paramStruct)
		selfAttributes = append(selfAttributes, "\t"+paramStruct)

		credentialDefs = append(credentialDefs, applicationHandler.GenerateCredentialStruct(credentialName, credential.Credential))

		var emptyAttrs string
		for _, attr := range credential.Credential.Spec.Attributes {
			if attr.Required {
				emptyAttrs += fmt.Sprintf(`
		if not self.%s:
			emptyAttrs.append("%s")
        		`, strcase.ToSnake(attr.Name), attr.Name)
			}
		}
		if len(credential.Credential.Spec.Attributes) == 0 {
			validateMethod = ""
		}
		validateMethod += emptyAttrs
	}
	if utils.IsNotEmpty(validateMethod) {
		validateMethod += `
		return "Invalid Credentials: " + ", ".join(emptyAttrs) + " is empty" if emptyAttrs else ""
`
	}
	applicationStructName := strcase.ToCamel(applicationVO.Meta.Name)

	LinkedApp := strings.NewReplacer("{{CLASS_NAME}}", "LinkedApplications",
		"{{PARAM_DECLARATION}}", strings.Join(linkedAppParamNames, ","),
		"{{PARAM_VALUE_DECLARATION}}", strings.Join(linkedAppDefaultValues, ","),
		"{{FROM_DICT_HANDLE}}", strings.Join(linkedAppFromDict, "\n"),
		"{{TO_DICT_HANDLE}}", strings.Join(linkedAppToDict, "\n"),
		"{{SELF_PARAM_DECLARATION}}", strings.Join(linkedAppsClassVariables, "\n"),
		"{{INIT_PARAM}}", strings.Join(linkedSelfParams, ","),
		"{{INIT_HELPER_METHODS}}", strings.Join(linkedAppInitHelperMethods, "\n"),
	).Replace(constants.PyStructHelper)

	LinkedAppClassSelfParam := constants.LinkedAppClassSelfParam
	LinkedAppInitParam := constants.LinkedAppInitParam
	LinkedAppInitSelfParam := constants.LinkedAppInitSelfParam
	LinkedAppToDictResultValue := constants.LinkedAppToDictResultValue
	LinkedAppFromDictResultValue := constants.LinkedAppFromDictResultValue
	LinkedAppStaticMethodVariable := constants.LinkedAppStaticMethodVariable
	ApplicationStaticMethodReturnValues := constants.ApplicationStaticMethodReturnValuesWithLinkedApp

	if !linkedApplicationAvailable {
		LinkedApp = ""
		LinkedAppClassSelfParam = ""
		LinkedAppInitParam = ""
		LinkedAppInitSelfParam = ""
		LinkedAppToDictResultValue = ""
		LinkedAppFromDictResultValue = ""
		LinkedAppStaticMethodVariable = ""
		ApplicationStaticMethodReturnValues = constants.ApplicationStaticMethodReturnValues
	}

	replacer := strings.NewReplacer("{{USER_DEFINED_CREDENTIAL_STRUCT_VO}}", strings.Join(credentialDefs, "\n\n"),
		"{{PARAM_DECLARATION}}", strings.Join(paramNames, ","),
		"{{PARAM_VALUE_DECLARATION}}", strings.Join(defaultValues, ","),
		"{{FROM_DICT_HANDLE}}", strings.Join(fromDict, "\n"),
		"{{TO_DICT_HANDLE}}", strings.Join(toDict, "\n"),
		"{{SELF_PARAM_DECLARATION}}", strings.Join(selfAttributes, "\n"),
		"{{INIT_PARAM}}", strings.Join(selfParams, ","),
		"{{INIT_HELPER_METHODS}}", strings.Join(initHelperMethods, "\n"),
		"{{APPLICATION_STRUCT_NAME}}", applicationStructName,
		"{{VALIDATE_METHODS}}", validateMethod,
		"{{LINKED_APPLICATIONS_IMPORTS}}", strings.Join(linkedAppsImports, "\n"),
		"{{LINKED_APPLICATION_CLASS}}", LinkedApp,
		"{{LINKED_APP_CLASS_SELF_PARAM}}", LinkedAppClassSelfParam,
		"{{LINKED_APP_STATIC_VARIABLE_DECLARE}}", LinkedAppStaticMethodVariable,
		"{{APPLICATION_STATIC_METHOD_RETURN_VALUES}}", ApplicationStaticMethodReturnValues,
		"{{LINKED_APP_INIT_PARAM}}", LinkedAppInitParam,
		"{{LINKED_APP_INIT_SELF_PARAM}}", LinkedAppInitSelfParam,
		"{{LINKED_APP_TO_DICT_RESULT}}", LinkedAppToDictResultValue,
		"{{LINKED_APP_FROM_DICT}}", LinkedAppFromDictResultValue,
	)

	fileData := replacer.Replace(constants.ApplicationStruct_Py)

	// formattedFileBytes, err := format.Source([]byte(fileData))
	// if err != nil {
	// 	return err
	// }

	if utils.IsEmpty(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationTypesPath) {
		additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationTypesPath = constants.CowDataAppConnectionPath
	}

	packageName := strings.ToLower(applicationVO.Meta.Name)

	// folderPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationTypesPath, "python", packageName, applicationVO.Meta.Version)

	folderPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationTypesPath, "python", filepath.Base(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationTypesPath), packageName)

	if utils.IsFolderNotExist(folderPath) {
		err := os.MkdirAll(folderPath, os.ModePerm)
		if err != nil {
			return err
		}
	}

	applicationPath := filepath.Join(folderPath, packageName+".py")

	err := os.WriteFile(applicationPath, []byte(fileData), os.ModePerm)
	if err != nil {
		return err
	}

	FormatPythonFile(applicationPath)

	err = os.WriteFile(filepath.Join(folderPath, "__init__.py"), []byte(``), os.ModePerm)
	if err != nil {
		return err
	}

	taskName := strcase.ToCamel("Validate" + applicationStructName)

	additionalInfo.IsTasksToBePrepare = true

	additionalInfo.AppCreateFlow = true

	validationTask := filepath.Join(folderPath, taskName)

	if utils.IsFolderExist(validationTask) {
		os.RemoveAll(validationTask)
	}

	err = (&task.PythonTask{}).InitTask(taskName, folderPath, nil, additionalInfo)

	if err != nil {
		return err
	}

	metaFilePath := filepath.Join(validationTask, "__meta.yaml")
	err = os.Remove(metaFilePath)
	if err != nil {
		return err
	}

	err = CreateTaskInputYAMLWithAppConfig(validationTask, applicationVO, credentialsMap)
	if err != nil {
		return err
	}

	return applicationHandler.ModifyAutoGeneratedTaskWithBaseValidationTask(taskName, folderPath, applicationVO)

}

func (applicationHandler *PythonApplicationHandler) GenerateCredentialStruct(structName string, credential *vo.UserDefinedCredentialVO) string {

	selfParams := make([]string, 0)
	fromDict := make([]string, 0)
	toDict := make([]string, 0)
	paramNames := make([]string, 0)
	defaultValues := make([]string, 0)
	selfAttributes := make([]string, 0)
	initHelperMethods := make([]string, 0)

	for _, attribute := range credential.Spec.Attributes {
		paramName := strcase.ToSnake(attribute.Name)
		paramNames = append(paramNames, paramName)
		defaultValue := `""`
		paramStruct := paramName + `:	`
		attributeType := "str"
		fromDictStr := "\t\t\t"
		toDictStr := "\t\t"
		// fromDictStr = "            "
		// toDictStr = "        "
		// fromDictStr = ""
		// toDictStr = ""
		if strings.Contains(strings.ToUpper(string(attribute.DataType)), string(vo.AttributeDataType_FLOAT)) {
			attributeType = "float"
			defaultValue = "0.0"

		} else if strings.ToUpper(string(attribute.DataType)) == string(vo.AttributeDataType_INT) {
			attributeType = "int"
			defaultValue = "0"
		}

		if attribute.MultiSelect {
			attributeType = `List[` + attributeType + `]`
			defaultValue = `[]`
		}

		fromDictStr += paramName + ` = obj.get("` + attribute.Name + `",` + defaultValue + `) `
		toDictStr += `result["` + attribute.Name + `"]=self.` + paramName

		initHelperMethods = append(initHelperMethods, "\t\tself."+paramName+" = "+paramName)
		// initHelperMethods = append(initHelperMethods, "        self."+paramName+" = "+paramName)
		// initHelperMethods = append(initHelperMethods, "self."+paramName+" = "+paramName)

		toDict = append(toDict, toDictStr)
		defaultValues = append(defaultValues, defaultValue)
		fromDict = append(fromDict, fromDictStr)

		paramStruct += attributeType

		selfParams = append(selfParams, paramStruct)

		selfAttributes = append(selfAttributes, "\t"+paramStruct)
		// selfAttributes = append(selfAttributes, ""+paramStruct)

	}
	if len(initHelperMethods) == 0 {
		initHelperMethods = append(initHelperMethods, "\t\tpass")
	}

	var paramAssignment string
	if len(paramNames) > 0 && len(defaultValues) > 0 {
		paramAssignment = fmt.Sprintf("%s = %s", strings.Join(paramNames, ","), strings.Join(defaultValues, ","))
	}
	var fromDictConditionalCheck string
	if len(fromDict) > 0 {
		fromDictConditionalCheck = "if isinstance(obj, dict):"
	}

	return strings.NewReplacer("{{CLASS_NAME}}", structName,
		"{{PARAM_DECLARATION}}", strings.Join(paramNames, ","),
		"{{PARAM_ASSIGNMENT}}", paramAssignment,
		"{{FROM_DICT_CONDITIONAL_CHECK}}", fromDictConditionalCheck,
		"{{FROM_DICT_HANDLE}}", strings.Join(fromDict, "\n"),
		"{{TO_DICT_HANDLE}}", strings.Join(toDict, "\n"),
		"{{SELF_PARAM_DECLARATION}}", strings.Join(selfAttributes, "\n"),
		"{{INIT_PARAM}}", strings.Join(selfParams, ","),
		"{{INIT_HELPER_METHODS}}", strings.Join(initHelperMethods, "\n"),
	).Replace(constants.PyStructHelper)

}

func (applicationHandler *PythonApplicationHandler) ModifyAutoGeneratedTaskWithBaseValidationTask(taskName, folderPath string, applicationVO *vo.UserDefinedApplicationVO) error {

	taskFolderPath := filepath.Join(folderPath, taskName)

	if utils.IsFolderNotExist(taskFolderPath) {
		return fmt.Errorf("cannot find the task path of %s", taskName)
	}

	appPackageName := strings.ToLower(applicationVO.Meta.Name)

	replacer := strings.NewReplacer("{{APPLICATION_PACKAGE_NAME}}", appPackageName,
		"{{VERSION}}", applicationVO.Meta.Version,
		"{{APPLICATION_PACKAGE_NAME}}", appPackageName,
		"{{TASK_NAME}}", taskName,
		"{{APP_CLASS_NAME}}", strcase.ToCamel(applicationVO.Meta.Name),
		"{{APP_STRUCT_NAME}}", strcase.ToCamel(applicationVO.Meta.Name))

	return os.WriteFile(filepath.Join(taskFolderPath, "task.py"), []byte(replacer.Replace(constants.ValidateTask_Py)), os.ModePerm)
}

func FormatPythonFile(filePath string) error {
	return exec.Command("python3", "-m", "yapf", "-i", filePath).Run()
}
