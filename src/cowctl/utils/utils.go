package utils

import (
	"cowlibrary/constants"
	cowlibutils "cowlibrary/utils"
	"cowlibrary/vo"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/briandowns/spinner"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"cowctl/utils/terminalutils"
	"cowctl/utils/terminalutils/dropdownutils"
	"cowctl/utils/validationutils"
)

const MaxLen = 120

func GetValueAsStrFromCmdPrompt(labelName string, isMandatory bool, validate func(input string) error) (string, error) {

	var value string
	var err error
	if validate != nil {
		value, err = terminalutils.GetValueFromCmdPrompt(labelName, MaxLen, validate)
	} else {
		value, err = terminalutils.GetValueAsStrFromCmdPrompt(labelName)
	}

	if err != nil {
		return "", err
	}

	if isMandatory && cowlibutils.IsEmpty(value) {
		return "", errors.New("cannot be empty")
	}

	return value, err
}

func GetValueAsIntFromCmdPrompt(labelName string, isMandatory bool, min, max int, validate func(input string) error) (int, error) {
	return terminalutils.GetValueAsIntFromCmdPrompt(labelName, min, max)
}

func GetValueAsFilePathFromCmdPrompt(labelName string, isMandatory bool, validate func(input string) error) (string, error) {
	return terminalutils.GetValueFromCmdPrompt(labelName, 2000, validate)
}

func GetValueAsFileNameFromCmdPrompt(labelName string, pathPrefix string, allowedFileTypes []string) (string, error) {
	dirEntries, err := os.ReadDir(pathPrefix)
	if err != nil {
		return "", err
	}

	files := make([]dropdownutils.Item, 0)
	for _, dirEntry := range dirEntries {

		if !dirEntry.IsDir() && (len(allowedFileTypes) == 0 || (cowlibutils.SliceContains(allowedFileTypes, filepath.Ext(dirEntry.Name())))) {
			fileName := strings.TrimSuffix(dirEntry.Name(), filepath.Ext(dirEntry.Name()))
			displayName := SplitCamelCase(fileName)
			if strings.Contains(fileName, "_") {
				nameAndVersion := strings.Split(fileName, "_v_")
				if len(nameAndVersion) == 2 {
					displayName = fmt.Sprintf("Name : %s , Version : %s", nameAndVersion[0], strings.ReplaceAll(nameAndVersion[1], "_", "."))
				}
			}

			files = append(files, dropdownutils.Item{Name: dirEntry.Name(), Descr: displayName})
		}
	}

	selectedValue, err := dropdownutils.GetOptionFromCmdPrompt(labelName, files)

	if cowlibutils.IsEmpty(selectedValue) {
		return selectedValue, errors.New("value cannot be empty")
	}

	if !strings.HasPrefix(strings.TrimSpace(labelName), ":") {
		labelName += ":"
	}

	fmt.Printf("%s %s \n", labelName, selectedValue)

	return selectedValue, err
}

func GetValueAsFolderNameFromCmdPrompt(labelName string, isMandatory bool, pathPrefix string, validate func(input string) error) (string, error) {

	dirEntry, err := os.ReadDir(pathPrefix)
	if err != nil {
		return "", err
	}

	directories := make([]dropdownutils.Item, 0)
	for _, dir := range dirEntry {
		if dir.IsDir() {
			directories = append(directories, dropdownutils.Item{Name: dir.Name(), Descr: SplitCamelCase(dir.Name())})
		}
	}

	selectedValue, err := dropdownutils.GetOptionFromCmdPrompt(labelName, directories)

	if isMandatory && cowlibutils.IsEmpty(selectedValue) {
		return selectedValue, errors.New("value cannot be empty")
	}

	if !strings.HasPrefix(strings.TrimSpace(labelName), ":") {
		labelName += ":"
	}

	fmt.Printf("%s %s \n", labelName, selectedValue)

	return selectedValue, err

}

func GetApplicationNamesForBinary(pathPrefixs []string) []dropdownutils.Item {
	directories := make([]dropdownutils.Item, 0)
	for _, pattern := range pathPrefixs {
		matches, _ := filepath.Glob(pattern)
		for _, path := range matches {
			files, err := os.ReadDir(path)
			if err != nil {
				continue
			}
			for _, file := range files {
				if filepath.Ext(file.Name()) == ".yaml" {
					filePath := filepath.Join(path, file.Name())
					yamlContent, err := os.ReadFile(filePath)
					if err != nil {
						continue
					}
					var data *vo.UserDefinedApplicationVO
					if err := yaml.Unmarshal(yamlContent, &data); err != nil {
						continue
					}
					fullPath := filepath.Join(path, file.Name())
					descr := fmt.Sprintf("Name :%s", data.Meta.DisplayName)
					if cowlibutils.IsNotEmpty(data.Meta.Version) {
						descr += " , Version :" + data.Meta.Version
					}
					directories = append(directories, dropdownutils.Item{Name: data.Meta.Name, Descr: descr, Path: fullPath})
				}
			}
		}
	}
	return directories
}

func GetApplicationNamesFromCmdPromptInCatalogs(labelName string, isMandatory bool, pathPrefixs []string) (*dropdownutils.Item, error) {
	directories := make([]dropdownutils.Item, 0)
	for _, pattern := range pathPrefixs {
		matches, _ := filepath.Glob(pattern)
		for _, path := range matches {
			files, err := os.ReadDir(path)
			if err != nil {
				continue
			}
			for _, file := range files {
				if filepath.Ext(file.Name()) == ".yaml" {
					filePath := filepath.Join(path, file.Name())
					yamlContent, err := os.ReadFile(filePath)
					if err != nil {
						continue
					}
					var data *vo.UserDefinedApplicationVO
					if err := yaml.Unmarshal(yamlContent, &data); err != nil {
						continue
					}
					fullPath := filepath.Join(path, file.Name())
					descr := fmt.Sprintf("Name :%s", data.Meta.DisplayName)
					if cowlibutils.IsNotEmpty(data.Meta.Version) {
						descr += " , Version :" + data.Meta.Version
					}
					directories = append(directories, dropdownutils.Item{Name: data.Meta.Name, Descr: descr, Path: fullPath})
				}
			}
		}
	}
	if len(directories) == 0 {
		return nil, errors.New("application class not found")
	}
	appName, err := getSelectedValue(labelName, isMandatory, directories, nil)
	if err != nil {
		return nil, err
	}
	for _, item := range directories {
		if item.Name == appName {
			return &item, nil
		}
	}
	return nil, errors.New("application class not found")
}

func GetPrimaryApplicationNamesFromSelectedApps(labelName string, isMandatory bool, selectedAppPaths []string) (*dropdownutils.Item, error) {
	directories := make([]dropdownutils.Item, 0)
	for _, appPath := range selectedAppPaths {
		if _, err := os.Stat(appPath); err == nil {
			yamlContent, err := os.ReadFile(appPath)
			if err != nil {
				continue
			}

			var data *vo.UserDefinedApplicationVO
			if err := yaml.Unmarshal(yamlContent, &data); err != nil {
				continue
			}

			descr := fmt.Sprintf("Name :%s", data.Meta.DisplayName)
			if cowlibutils.IsNotEmpty(data.Meta.Version) {
				descr += " , Version :" + data.Meta.Version
			}
			directories = append(directories, dropdownutils.Item{Name: data.Meta.Name, Descr: descr, Path: appPath})
		}
	}

	if len(directories) == 0 {
		return nil, errors.New("no selected applications found")
	}

	appName, err := getSelectedValue(labelName, isMandatory, directories, nil)
	if err != nil {
		return nil, err
	}

	for _, item := range directories {
		if item.Name == appName {
			return &item, nil
		}
	}
	return nil, errors.New("application class not found")
}

func GetApplicationWithCredential(filePath string, directory string) (*vo.ApplicationInfoVO, error) {
	applicationInfoVO := vo.ApplicationInfoVO{}
	applicationYamlContent, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var appData *vo.UserDefinedApplicationVO
	if err := yaml.Unmarshal(applicationYamlContent, &appData); err != nil {
		return nil, err
	}
	applicationInfoVO.App = appData
	userDefinedCredentials, err := GetAvailableCredntialsFromAppClass(directory)
	if err != nil {
		return nil, err
	}
	credentials := make([]*vo.UserDefinedCredentialVO, 0)
	for _, credentialType := range appData.Spec.CredentialTypes {
		for _, userDefinedCredential := range userDefinedCredentials {
			if userDefinedCredential.Meta.Name == credentialType.Name && userDefinedCredential.Meta.Version == credentialType.Version {
				credentials = append(credentials, userDefinedCredential)
			}
		}
	}
	applicationInfoVO.Credential = credentials

	applicationInfoVO.App.AppTags = appData.Meta.Labels

	linkedApplications := appData.Spec.LinkableApplicationClasses
	if len(linkedApplications) > 0 {
		linkedApplicationsInfo, err := GetLinkedApplicationsDetails(linkedApplications, filePath, directory)
		if err != nil {
			fmt.Println("Error occurred while getting linked applications details : ", err)
			return nil, err
		}
		applicationInfoVO.LinkedApplications = linkedApplicationsInfo
	}
	return &applicationInfoVO, nil

}

func GetLinkedApplicationsDetails(linkedApplications []*vo.CowNamePointersVO, filePath string, directory string) ([]*vo.ApplicationInfoVO, error) {
	linkedApplicationsInfo := make([]*vo.ApplicationInfoVO, 0)
	for _, linkedApp := range linkedApplications {
		newFileName := linkedApp.Name + ".yaml"
		applicationInfo, err := GetApplicationWithCredential(replaceFilename(filePath, newFileName), directory)
		if err != nil {
			return nil, err
		}
		linkedApplicationsInfo = append(linkedApplicationsInfo, applicationInfo)
	}
	return linkedApplicationsInfo, nil
}

func replaceFilename(filePath, newFilename string) string {
	dir := filepath.Dir(filePath)
	return filepath.Join(dir, newFilename)
}

func GetAvailableCredntialsFromAppClass(directory string) ([]*vo.UserDefinedCredentialVO, error) {
	userDefinedCredentials := make([]*vo.UserDefinedCredentialVO, 0)
	files, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".yaml" {
			filePath := filepath.Join(directory, file.Name())
			yamlContent, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}
			var data *vo.UserDefinedCredentialVO
			if err := yaml.Unmarshal(yamlContent, &data); err != nil {
				continue
			}
			userDefinedCredentials = append(userDefinedCredentials, data)
		}
	}
	return userDefinedCredentials, nil
}

func GetValueAsFolderNameFromCmdPromptInCatalogs(labelName string, isMandatory bool, pathPrefixs []string, validate func(input string) error, additionalInfo *vo.AdditionalInfo) (string, error) {

	directories := make([]dropdownutils.Item, 0)
	for _, pattern := range pathPrefixs {
		description := "The Resource is present in "
		isGlobal := true
		if strings.Contains(pattern, "localcatalog") {
			isGlobal = false
			description += "localcatalog"
		} else {
			description += "globalcatalog"

		}
		matches, _ := filepath.Glob(pattern)
		for _, path := range matches {

			if strings.Contains(path, "localcatalog") {
				domain := filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(path))))
				if filepath.Base(domain) != "localcatalog" {
					description += " in " + filepath.Base(domain) + " domain"
				}
			}
			name := filepath.Base(filepath.Dir(path))
			if filepath.Ext(path) == ".yaml" && filepath.Base(path) != "rule.yaml" && filepath.Base(path) != constants.RuleGroupYAMLFileName {
				name = filepath.Base(path)
			}
			directories = append(directories, dropdownutils.Item{Name: name, Descr: description, Global: isGlobal})
		}
	}
	return getSelectedValue(labelName, isMandatory, directories, additionalInfo)
}

func getSelectedValue(labelName string, isMandatory bool, directories []dropdownutils.Item, additionalInfo *vo.AdditionalInfo) (string, error) {
	selectedValue, err := dropdownutils.GetOptionFromCmdPromptV2(labelName, directories, additionalInfo)

	if isMandatory && cowlibutils.IsEmpty(selectedValue) {
		return selectedValue, errors.New("value cannot be empty")
	}

	if !strings.HasPrefix(strings.TrimSpace(labelName), ":") {
		labelName += ":"
	}

	fmt.Printf("%s %s \n", labelName, selectedValue)

	return selectedValue, err
}

func GetConfirmationFromCmdPrompt(labelName string) (bool, error) {
	return terminalutils.GetConfirmationFromCmdPrompt(labelName)
}

type CowctlOption interface {
	bool | string
}

func GetConfirmationFromCmdPromptWithOptions(labelName, defaultOption string, options []string) (string, error) {
	return terminalutils.GetOptionFromCmdPrompt(labelName, defaultOption, options)
}

func IsCmdTerminationError(err error) bool {
	return err != nil && (err.Error() == "^C" || err.Error() == "^D")
}

type Exit int

func HandleTermination(err error) {
	defer HandleExit()
	if err != nil {
		if err.Error() == "^C" || err.Error() == "^D" {
			panic(Exit(0))
		}
	}
}

func HandleExit() {
	switch v := recover().(type) {
	case nil:
		return
	case Exit:
		HandleCmdFunkyness()
		os.Exit(int(v))
	default:
		fmt.Println(v)
		HandleCmdFunkyness()
	}
}

func HandleCmdFunkyness() {
	cmd := exec.Command("stty", "sane")
	cmd.Stdin = os.Stdin
	cmd.Output()
}

func GetTaskLanguage(taskPath string) constants.SupportedLanguage {

	taskMainFilePath := taskPath

	if !strings.HasSuffix(taskMainFilePath, "/") {
		taskMainFilePath += "/"
	}

	switch {
	case cowlibutils.IsFileExist(taskMainFilePath + constants.AutoGeneratedFilePrefix + "main.py"):
		return constants.SupportedLanguagePython
	default:
		return constants.SupportedLanguageGo
	}

}

func GetDefaultConfigInfo() *vo.PolicyCowConfig {
	policyCowConfig := &vo.PolicyCowConfig{
		Version: "1.0",
		PathConfiguration: &vo.CowPathConfiguration{
			TasksPath:            constants.CowDataTaskPath,
			RulesPath:            constants.CowDataRulesPath,
			ExecutionPath:        constants.CowDataExecutionsPath,
			RuleGroupPath:        constants.CowDataRuleGroupPath,
			SynthesizersPath:     constants.CowDataSynthesizerPath,
			DownloadsPath:        constants.CowDataDownloadsPath,
			YamlFilesPath:        constants.CowDataYamlFilesPath,
			ApplicationScopePath: constants.CowDataApplicationScopePath,
			DeclarativePath:      constants.CowDataDeclarativesFilesPath,
			AppConnectionPath:    constants.CowDataAppConnectionPath,
			ApplicationClassPath: constants.CowApplicationClassPath,
			CredentialsPath:      constants.CowCredentialsPath,
		},
	}

	configFilePath := constants.CowDataDefaultConfigFilePath

	if configFromENV, isPresent := os.LookupEnv("COWCTL_CONFIG"); isPresent {
		configFilePath = configFromENV
	}

	isJSONConfig := strings.HasSuffix(configFilePath, ".json")

	if !cowlibutils.IsFileExist(configFilePath) {
		byts, err := yaml.Marshal(policyCowConfig)
		if isJSONConfig {
			byts, err = json.Marshal(policyCowConfig)
		}

		if err != nil {
			// TODO: As of now we're ignoring
		}

		configDirectory := filepath.Dir(configFilePath)

		if _, err := os.Stat(configDirectory); os.IsNotExist(err) {
			err := os.Mkdir(configDirectory, os.ModePerm)
			if err != nil {
				fmt.Printf("cannot create the config file %s:", err)
				panic(err)
			}
		}

		if err == nil {
			err := os.WriteFile(configFilePath, byts, os.ModePerm)
			if err != nil {
				fmt.Println("err while creating config :::")
			}
		}
		return policyCowConfig
	}

	if cowlibutils.IsFileExist(configFilePath) {
		byts, err := os.ReadFile(configFilePath)
		if err == nil {
			yaml.Unmarshal(byts, policyCowConfig)
		}
	}

	return policyCowConfig
}

func GetConfigInfoWithPath(path string) (*vo.PolicyCowConfig, error) {
	if cowlibutils.IsEmpty(path) || path == constants.CowDataDefaultConfigFilePath {
		return GetDefaultConfigInfo(), nil
	}

	return cowlibutils.GetConfigFromFile(path)
}

func GetCommonFlagsAndBuildConfig(cmd *cobra.Command) (*vo.PolicyCowConfig, error) {
	configPath, rulesPath, taskPath, executionPath, ruleGroupPath, synthesizerPath, declarativesPath, appConnectionPath, applicationClassPath, credentialsPath :=
		constants.CowDataDefaultConfigFilePath, constants.CowDataRulesPath, constants.CowDataTaskPath, constants.CowDataExecutionsPath, constants.CowDataRuleGroupPath,
		constants.CowDataSynthesizerPath, constants.CowDataDeclarativesFilesPath, constants.CowDataAppConnectionPath, constants.CowApplicationClassPath, constants.CowCredentialsPath
	if cmd.Flags().HasFlags() {
		if flagName := cmd.Flags().Lookup("config-path"); flagName != nil && flagName.Changed {
			configPath = flagName.Value.String()
		}
	}
	downloadsPath := constants.CowDataDownloadsPath
	policyCowConfig, err := GetConfigInfoWithPath(configPath)

	if err != nil {
		return nil, err
	}
	if cmd.Flags().HasFlags() {

		if rulesPath := GetFlagValueAndResetFlag(cmd, "rules-path", ""); cowlibutils.IsNotEmpty(rulesPath) {
			policyCowConfig.PathConfiguration.RulesPath = rulesPath
		}
		if tasksPath := GetFlagValueAndResetFlag(cmd, "tasks-path", ""); cowlibutils.IsNotEmpty(tasksPath) {
			policyCowConfig.PathConfiguration.TasksPath = tasksPath
		}
		if execPath := GetFlagValueAndResetFlag(cmd, "exec-path", ""); cowlibutils.IsNotEmpty(execPath) {
			policyCowConfig.PathConfiguration.ExecutionPath = execPath
		}
		if ruleGroupPath := GetFlagValueAndResetFlag(cmd, "rule-group-path", ""); cowlibutils.IsNotEmpty(ruleGroupPath) {
			policyCowConfig.PathConfiguration.RuleGroupPath = ruleGroupPath
		}
		if synthesizersPath := GetFlagValueAndResetFlag(cmd, "synthesizer-path", ""); cowlibutils.IsNotEmpty(synthesizersPath) {
			policyCowConfig.PathConfiguration.SynthesizersPath = synthesizersPath
		}
		if downloadsPath := GetFlagValueAndResetFlag(cmd, "downloads-path", ""); cowlibutils.IsNotEmpty(downloadsPath) {
			policyCowConfig.PathConfiguration.DownloadsPath = downloadsPath
		}

	}

	if cowlibutils.IsEmpty(policyCowConfig.PathConfiguration.RulesPath) {
		policyCowConfig.PathConfiguration.RulesPath = rulesPath
	}
	if cowlibutils.IsEmpty(policyCowConfig.PathConfiguration.TasksPath) {
		policyCowConfig.PathConfiguration.TasksPath = taskPath
	}
	if cowlibutils.IsEmpty(policyCowConfig.PathConfiguration.ExecutionPath) {
		policyCowConfig.PathConfiguration.ExecutionPath = executionPath
	}
	if cowlibutils.IsEmpty(policyCowConfig.PathConfiguration.RuleGroupPath) {
		policyCowConfig.PathConfiguration.RuleGroupPath = ruleGroupPath
	}
	if cowlibutils.IsEmpty(policyCowConfig.PathConfiguration.SynthesizersPath) {
		policyCowConfig.PathConfiguration.SynthesizersPath = synthesizerPath
	}
	if cowlibutils.IsEmpty(policyCowConfig.PathConfiguration.DownloadsPath) {
		policyCowConfig.PathConfiguration.DownloadsPath = downloadsPath
	}

	if cowlibutils.IsEmpty(policyCowConfig.PathConfiguration.DeclarativePath) {
		policyCowConfig.PathConfiguration.DeclarativePath = declarativesPath
	}

	if cowlibutils.IsEmpty(policyCowConfig.PathConfiguration.AppConnectionPath) {
		policyCowConfig.PathConfiguration.AppConnectionPath = appConnectionPath
	}

	if cowlibutils.IsEmpty(policyCowConfig.PathConfiguration.ApplicationClassPath) {
		policyCowConfig.PathConfiguration.ApplicationClassPath = applicationClassPath
	}

	if cowlibutils.IsEmpty(policyCowConfig.PathConfiguration.CredentialsPath) {
		policyCowConfig.PathConfiguration.CredentialsPath = credentialsPath
	}

	if policyCowConfig.UserData == nil {
		policyCowConfig.UserData = &vo.UserData{}
	}

	if cowlibutils.IsEmpty(policyCowConfig.UserData.Credentials.Compliancecow.ClientID) {

		policyCowConfig.UserData.Credentials.Compliancecow.ClientID = constants.CowClientID
	}

	if cowlibutils.IsEmpty(policyCowConfig.UserData.Credentials.Compliancecow.ClientSecret) {
		policyCowConfig.UserData.Credentials.Compliancecow.ClientSecret = constants.CowClientSecret
	}

	if cowlibutils.IsEmpty(policyCowConfig.UserData.Credentials.Compliancecow.SubDomain) {
		policyCowConfig.UserData.Credentials.Compliancecow.SubDomain = constants.CowPublishSubDomain
	}
	return policyCowConfig, nil

}

func GetAdditionalInfoFromCmd(cmd *cobra.Command) (*vo.AdditionalInfo, error) {
	policyCowConfig, err := GetCommonFlagsAndBuildConfig(cmd)
	if err != nil {
		return nil, err
	}
	additionalInfo := &vo.AdditionalInfo{PolicyCowConfig: policyCowConfig}
	catalogFlag := GetFlagValueAndResetFlag(cmd, "catalog", "")
	if cowlibutils.IsNotEmpty(catalogFlag) && catalogFlag != "globalcatalog" {
		return nil, fmt.Errorf("catalog can only accept 'globalcatalog' as value ")
	}
	additionalInfo.GlobalCatalog = cowlibutils.IsNotEmpty(catalogFlag) && catalogFlag == "globalcatalog"
	return additionalInfo, nil
}

func IsValidExportFileType(additionalType string) bool {
	return cowlibutils.IsNotEmpty(additionalType) && (additionalType == "tar" || additionalType == "zip")
}

func DrawErrorTable(errorDetailsVOs []*vo.ErrorDetailVO) {
	table := tablewriter.NewWriter(os.Stdout)

	table.SetHeader([]string{"Issue", "Location"})

	table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor})

	for _, errorDetailsVO := range errorDetailsVOs {

		row := []string{errorDetailsVO.Issue, errorDetailsVO.Location}
		table.Rich(row, []tablewriter.Colors{tablewriter.Colors{}, tablewriter.Colors{tablewriter.Bold, tablewriter.FgRedColor}})
	}

	table.SetCaption(true, "** This is a basic validation. Please check the source code to fix the errors.")
	table.Render()

}

func GetFlagValueAndResetFlag(cmd *cobra.Command, flagName, defaultValue string) string {
	if cmd.Flags().HasFlags() {
		if currentFlag := cmd.Flags().Lookup(flagName); currentFlag != nil && currentFlag.Changed {
			if flagValue := currentFlag.Value.String(); cowlibutils.IsNotEmpty(flagValue) {
				currentFlag.Value.Set("")
				return flagValue
			}
		}
	}
	return defaultValue
}

func StopSpinner(s *spinner.Spinner) {
	if s.Active() {
		s.Stop()
	}
}

func SplitCamelCase(input string) string {
	var result string
	for i, char := range input {
		// Add a space before uppercase letters (excluding the first letter)
		if i > 0 && 'A' <= char && char <= 'Z' && char != ' ' {
			result += " "
		}
		result += string(char)
	}
	return result
}

func GetTaskNameFromCmdPromptInCatalogs(labelName string, isMandatory bool, availableTasks []string, catalogTypes []string) (string, error) {
	if len(availableTasks) == 0 {
		return "", errors.New("no existing tasks found")
	}
	taskItems := make([]dropdownutils.Item, 0)
	for i, taskName := range availableTasks {
		var descr string
		if catalogTypes != nil {
			if catalogTypes[i] == "globalcatalog" {
				descr = "The task is in Global Catalog"
			} else {
				descr = "The task is in Local Catalog"
			}
		}

		taskItems = append(taskItems, dropdownutils.Item{Name: taskName, Descr: descr})
	}

	selectedTask, err := getSelectedValue(labelName, isMandatory, taskItems, nil)
	if err != nil {
		return "", err
	}
	return selectedTask, nil
}

var ValidateString = validationutils.ValidateString

var ValidateVersion = validationutils.ValidateVersion

var ValidateName = validationutils.ValidateName

var ValidateFilePath = validationutils.ValidateFilePath

var ValidateInt = validationutils.ValidateInt
