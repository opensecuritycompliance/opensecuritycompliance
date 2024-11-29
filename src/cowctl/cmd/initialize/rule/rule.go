package rule

import (
	"cowlibrary/constants"
	rule "cowlibrary/rule"
	task "cowlibrary/task"
	cowlibutils "cowlibrary/utils"
	"cowlibrary/vo"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kyokomi/emoji"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	taskJson "cowctl/cmd/initialize/task"
	"cowctl/utils"
	"cowctl/utils/validationutils"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args: cobra.NoArgs,

		Use:   "rule",
		Short: "Initialize the rule",
		Long:  "Initialize the rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd)
		},
	}

	cmd.Flags().StringP("name", "n", "", "Set your rule name")
	cmd.Flags().String("path", "", "path of the rule.")
	cmd.Flags().String("rules-path", "", "path of the rules folder.")
	cmd.Flags().String("tasks-path", "", "path of the tasks.")
	cmd.Flags().String("tasks-json-path", "", "json path for tasks.")
	cmd.Flags().String("config-path", "", "path for the configuration file.")
	cmd.Flags().String("catalog", "", `use "globalcatalog" to init rule in globalcatalog/rules`)
	cmd.Flags().Bool("can-override", false, "rule already exists in the system")
	cmd.Flags().Bool("binary", false, "whether using cowctl binary")

	return cmd
}

func runE(cmd *cobra.Command) error {
	additionalInfo, err := utils.GetAdditionalInfoFromCmd(cmd)
	if err != nil {
		return err
	}
	ruleName := ``
	path := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath, "rules")
	if additionalInfo.GlobalCatalog {
		path = additionalInfo.PolicyCowConfig.PathConfiguration.RulesPath
	}
	isDefaultConfigPath := cowlibutils.IsDefaultConfigPath(constants.CowDataDefaultConfigFilePath)

	if currentFlag := cmd.Flags().Lookup("can-override"); currentFlag != nil && currentFlag.Changed {
		if flagValue := currentFlag.Value.String(); cowlibutils.IsNotEmpty(flagValue) {
			currentFlag.Value.Set("false")
			additionalInfo.CanOverride, _ = strconv.ParseBool(flagValue)
		}
	}

	binaryEnabled, _ := cmd.Flags().GetBool("binary")
	if !binaryEnabled {
		if cmd.Flags().HasFlags() {
			ruleName = utils.GetFlagValueAndResetFlag(cmd, "name", "")
			path = utils.GetFlagValueAndResetFlag(cmd, "path", path)
		}
	
		if cowlibutils.IsNotEmpty(path) && cowlibutils.IsFolderNotExist(path) {
			isConfirmed, err := utils.GetConfirmationFromCmdPrompt("Path is not available. Are you going to initialize the folder ?")
			if !isConfirmed || err != nil {
				return err
			}
	
			err = os.MkdirAll(path, os.ModePerm)
			if err != nil {
				return err
			}
	
		}

		ruleGetLabelName := "Rule Name (only alphabets and numbers and must start with a capital letter)"

		if cowlibutils.IsNotEmpty(ruleName) {
			err := validationutils.ValidateAlphaNumeric(ruleName)
			if err != nil {
				ruleGetLabelName = "Please enter a valid rule name(only alphabets and numbers and must start with a capital letter)"
				ruleName = ""
			}
		}
	
		if cowlibutils.IsEmpty(ruleName) {
			ruleNameFromCmd, err := utils.GetValueAsStrFromCmdPrompt(ruleGetLabelName, true, validationutils.ValidateAlphaNumeric)
			if err != nil || cowlibutils.IsEmpty(ruleNameFromCmd) {
				return err
			}
			ruleName = ruleNameFromCmd
		}
	
		rulePath, err := cowlibutils.GetRulePath(path, ruleName)
	
		if err != nil {
			return err
		}

		if cowlibutils.IsFolderExist(rulePath) && !additionalInfo.CanOverride {
			if !isDefaultConfigPath && !additionalInfo.CanOverride {
				return fmt.Errorf("The rule is already present in the system. To want to re-initialize again, set the 'can-override' flag as true")
			}

			isConfirmed, err := utils.GetConfirmationFromCmdPrompt("Rule already presented in the directory. Are you sure you going to re-initialize ?")
			if !isConfirmed || err != nil {
				return err
			}
	
			err = cowlibutils.RemoveChildrensFromFolder(rulePath)
			if err != nil {
				return err
			}
	
		}


		taskNameMap := make(map[string]struct{}, 0)
	
		taskCount, err := utils.GetValueAsIntFromCmdPrompt("Enter the task count", true, 1, 5, utils.ValidateInt)
		if err != nil || taskCount == -1 {
			return err
		}
		additionalInfo.ApplicationInfo = make([]*vo.ApplicationInfoVO, taskCount)

		taskNames := make([]*vo.TaskInputVO, 0)
	
		var taskPaths = make([]string, 0)
		var useExistingTasks = make([]bool, 0)

		availableTasks := cowlibutils.GetTasksV2(additionalInfo)
		availableTaskNames := make([]string, len(availableTasks))
		catalogTypes := make([]string, len(availableTasks))
		selectedTaskNames := make(map[string]bool)
		for i, task := range availableTasks {
			availableTaskNames[i] = task.Name
			catalogTypes[i] = task.CatalogType
		}
		if taskCount > 0 {
			for i := 1; i <= taskCount; i++ {
				var taskPath string
				var existingTask bool
				emoji.Println(fmt.Sprintf("\nLet’s get started on Task %d :smiling_face_with_sunglasses:", i))

				if len(availableTaskNames) > 0 {
					useExistingTask, err := utils.GetConfirmationFromCmdPrompt("Would you like to use existing tasks? (inputs.yaml will be change based on app selection)")
					if err != nil {
						return err
					}
					if useExistingTask {
						existingTask = true

						selectedTaskName, err := utils.GetTaskNameFromCmdPromptInCatalogs("Select the existing task ", true, availableTaskNames, catalogTypes)
						if err != nil {
							return err
						}
	
						taskPath = cowlibutils.GetTaskPathFromCatalogForInit(additionalInfo, selectedTaskName, existingTask)
						inputYAMLFileByts, err := os.ReadFile(filepath.Join(taskPath, constants.TaskInputYAMLFile))
						if err != nil {
							return err
						}
						var appInfo vo.TaskInputV2
						err = yaml.Unmarshal(inputYAMLFileByts, &appInfo)
						if err != nil {
							return fmt.Errorf("not a valid rule input structure. error :%s", err.Error())
						}
						if appInfo.UserObject != nil && appInfo.UserObject.App != nil {
							applicationName := appInfo.UserObject.App.ApplicationName
							appClassPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationClassPath, fmt.Sprintf("%s.yaml", applicationName))
							applicationInfo, err := utils.GetApplicationWithCredential(appClassPath, additionalInfo.PolicyCowConfig.PathConfiguration.CredentialsPath)
							if err != nil {
								return err
							}
							additionalInfo.ApplicationInfo[i-1] = applicationInfo
						}
						languageFromPath := cowlibutils.GetTaskLanguage(taskPath)
						languageFromCmd := languageFromPath.String()
						taskNames = append(taskNames, &vo.TaskInputVO{TaskName: selectedTaskName, Language: languageFromCmd})
						emoji.Println("\n", selectedTaskName, " is selected :smiling_face_with_sunglasses: ")
						if i < taskCount {
							emoji.Println("\nChoose the next task or create a new task :person_surfing_tone1: ")
						}

						compareSelectedTaskName := strings.ToLower(selectedTaskName)
						selectedTaskNames[compareSelectedTaskName] = true
					} else {
						existingTask = false
					}
				}
				if !existingTask {
					label := fmt.Sprintf("Enter the task '%d' name (only alphabets and numbers and must start with a capital letter):", i)
				TaskNameGetter:
					taskNameFromCmd, err := utils.GetValueAsStrFromCmdPrompt(label, true, validationutils.ValidateAlphaNumeric)
					if err != nil || cowlibutils.IsEmpty(taskNameFromCmd) {
						return err
					}
					compareTaskName := strings.ToLower(taskNameFromCmd)
					if selectedTaskNames[compareTaskName] {
						label = fmt.Sprintf("The task name has already been provided.\nEnter the task '%d' name (only alphabets and numbers and must start with a capital letter):", i)
						goto TaskNameGetter
					}
					if _, ok := taskNameMap[compareTaskName]; ok {
						label = fmt.Sprintf("The task name has already been provided.\nEnter the task '%d' name (only alphabets and numbers and and must start with a capital letter):", i)
						goto TaskNameGetter
					}
	
					for _, taskName := range availableTaskNames {
						taskName = strings.ToLower(taskName)
						if taskName == compareTaskName {
							existingTask = true
							isConfirmed, err := utils.GetConfirmationFromCmdPrompt("Task already presented in the directory. Are you sure you going to re-initialize ?")
	
							if err != nil {
								return err
							}
	
							if !isConfirmed {
								goto TaskNameGetter
							}
							taskPath = cowlibutils.GetTaskPathFromCatalogForInit(additionalInfo, taskNameFromCmd, existingTask)
							err = cowlibutils.RemoveChildrensFromFolder(taskPath)
							if err != nil {
								return err
							}
							
						} else {
							existingTask = false
							taskPath = cowlibutils.GetTaskPathFromCatalogForInit(additionalInfo, taskNameFromCmd, existingTask)
						}
					}
	
					languageFromCmd, err := utils.GetConfirmationFromCmdPromptWithOptions("Select the programming language for task "+strconv.Itoa(i)+" python/go (default:go):", "go", []string{"go", "python"})
					if err != nil || cowlibutils.IsEmpty(taskNameFromCmd) {
						languageFromCmd = "go"
					}
					addApplication, err := utils.GetConfirmationFromCmdPrompt("Would you like to add Application ? ")
					if err != nil {
						return err
					}
					if addApplication {
						selectedAppItem, err := utils.GetApplicationNamesFromCmdPromptInCatalogs("Select the application class : ", true, []string{additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationClassPath})
						if err != nil {
							return err
						}
						applicationInfo, err := utils.GetApplicationWithCredential(selectedAppItem.Path, additionalInfo.PolicyCowConfig.PathConfiguration.CredentialsPath)
						if err != nil {
							return err
						}
						additionalInfo.ApplicationInfo[i-1] = applicationInfo
					}

					taskNameMap[compareTaskName] = struct{}{}
	
					taskNames = append(taskNames, &vo.TaskInputVO{TaskName: taskNameFromCmd, Language: languageFromCmd})
	
					selectedTaskNames[compareTaskName] = true
				}
				taskPaths = append(taskPaths, taskPath)
				useExistingTasks = append(useExistingTasks, existingTask)
			}
		}

		var primaryAppInfo *vo.ApplicationInfoVO
		selectedAppPaths := make(map[string]struct{})

		for _, appInfo := range additionalInfo.ApplicationInfo {
			if appInfo != nil {
				path := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationClassPath, fmt.Sprintf("%s.yaml", appInfo.App.Meta.Name))
				selectedAppPaths[path] = struct{}{}
			}
		}

		if len(selectedAppPaths) == 0 {
			if len(taskNames) > 1 {
				addAppToTask, err := utils.GetConfirmationFromCmdPrompt("None of the tasks have an application. At least one task must have an application. If you choose 'no', the process will terminate. Do you want to add an application now? (yes/no)")
				if !addAppToTask || err != nil {
					return err
				}
				taskNamesForApp := make([]string, 0, len(taskNames))
				for _, task := range taskNames {
					taskNamesForApp = append(taskNamesForApp, task.TaskName)
				}

				selectedTaskForApp, err := utils.GetTaskNameFromCmdPromptInCatalogs("Select the task to which you want to add an application:", true, taskNamesForApp, nil)
				if err != nil {
					return err
				}
				selectedAppItem, err := utils.GetApplicationNamesFromCmdPromptInCatalogs("Select the application class to add to the task:", true, []string{additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationClassPath})
				if err != nil {
					return err
				}
				applicationInfo, err := utils.GetApplicationWithCredential(selectedAppItem.Path, additionalInfo.PolicyCowConfig.PathConfiguration.CredentialsPath)
				if err != nil {
					return err
				}
				for i, task := range taskNames {
					if task.TaskName == selectedTaskForApp {
						additionalInfo.ApplicationInfo[i] = applicationInfo
						path := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationClassPath, fmt.Sprintf("%s.yaml", applicationInfo.App.Meta.Name))
						selectedAppPaths[path] = struct{}{}
						break
					}
				}
			} else {
				addAppConfirmation, err := utils.GetConfirmationFromCmdPrompt("There is no application assigned to this task. If you choose 'no', the process will terminate. Would you like to add application? (yes/no)")
				if !addAppConfirmation || err != nil {
					return err
				}
				selectedAppItem, err := utils.GetApplicationNamesFromCmdPromptInCatalogs("Select the application class to add to the task:", true, []string{additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationClassPath})
				if err != nil {
					return err
				}
				applicationInfo, err := utils.GetApplicationWithCredential(selectedAppItem.Path, additionalInfo.PolicyCowConfig.PathConfiguration.CredentialsPath)
				if err != nil {
					return err
				}
				additionalInfo.ApplicationInfo[0] = applicationInfo
				path := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationClassPath, fmt.Sprintf("%s.yaml", applicationInfo.App.Meta.Name))
				selectedAppPaths[path] = struct{}{}
			}
		}

		if len(selectedAppPaths) == 1 {
			for path := range selectedAppPaths {
				primaryAppInfo, err = utils.GetApplicationWithCredential(path, additionalInfo.PolicyCowConfig.PathConfiguration.CredentialsPath)
				if err != nil {
					return err
				}
			}
		} else if len(selectedAppPaths) > 1 {
			selectedAppList := make([]string, 0, len(selectedAppPaths))
			for path := range selectedAppPaths {
				selectedAppList = append(selectedAppList, path)
			}

			selectedAppItem, err := utils.GetPrimaryApplicationNamesFromSelectedApps("Select the primary application:", true, selectedAppList)
			if err != nil {
				return err
			}

			primaryAppInfo, err = utils.GetApplicationWithCredential(selectedAppItem.Path, additionalInfo.PolicyCowConfig.PathConfiguration.CredentialsPath)
			if err != nil {
				return err
			}
		}

		additionalInfo.PrimaryApplicationInfo = primaryAppInfo

		directoryPath, err := rule.InitRule(ruleName, path, taskNames, additionalInfo)
		if err != nil {
			return err
		}
		additionalInfo.Path = directoryPath
		emoji.Println(ruleName, "Rule is created :smiling_face_with_sunglasses: you can find the rule at ", directoryPath)
		tasksPath := filepath.Dir(directoryPath)
		if filepath.Base(tasksPath) == "rules" {
			tasksPath = filepath.Join(filepath.Dir(tasksPath), "tasks")
		} else {
			tasksPath = filepath.Join(tasksPath, "tasks")
		}
		if len(taskNames) > 0 {
			for id, taskName := range taskNames {
				var supportedLang constants.SupportedLanguage
				supportedLanguage, err := supportedLang.GetSupportedLanguage(taskName.Language)
				if err != nil {
					return err
				}
				languageSpecificTask := task.GetTask(*supportedLanguage)
				// TODO : Give an option to override with flag
				additionalInfo.IsTasksToBePrepare = true
				if useExistingTasks[id] {
					taskPaths[id] = filepath.Dir(taskPaths[id])
				} else {
					err = languageSpecificTask.InitTask(taskName.TaskName, tasksPath, &vo.TaskInputVO{}, additionalInfo)
				}
				if err != nil {
					return err
				}
				if useExistingTasks[id] {
					emoji.Println(taskName.TaskName, " Task is selected :smiling_face_with_sunglasses: you can find the task at ", filepath.Join(taskPaths[id], taskName.TaskName))
				} else {
					emoji.Println(taskName.TaskName, " Task is created :smiling_face_with_sunglasses: you can find the task at ", filepath.Join(tasksPath, taskName.TaskName))
				}
			}
		}
	
		emoji.Println(" Rule creation is now complete :smiling_face_with_sunglasses:! You can start coding!!:person_surfing_tone1:")
		additionalInfo.GlobalCatalog = false
	} else {
		ruleName = utils.GetFlagValueAndResetFlag(cmd, "name", "")
		path = utils.GetFlagValueAndResetFlag(cmd, "path", path)
		taskJsonPath := utils.GetFlagValueAndResetFlag(cmd, "tasks-json-path", "")

		file, err := os.Open(taskJsonPath)
		if err != nil {
			return err
		}
		defer file.Close()

		byteValue, err := io.ReadAll(file)
		if err != nil {
			return err
		}
		
		var tasks []taskJson.TaskJson
		if err := json.Unmarshal(byteValue, &tasks); err != nil {
			return err
		}

		taskNames := make([]*vo.TaskInputVO, 0)

		for _, taskData := range tasks {
			currentTask := vo.TaskInputVO{}
			currentTask.TaskName = taskData.Name
			
			currentTask.Language = taskData.Language
			var supportedLang constants.SupportedLanguage
			supportedLanguage, err := supportedLang.GetSupportedLanguage(currentTask.Language)
			if err != nil {
				return err
			}
			currentTask.Language = supportedLanguage.String()

			applicationpath := taskData.ApplicationPath

			applicationInfo, err := utils.GetApplicationWithCredential(applicationpath, additionalInfo.PolicyCowConfig.PathConfiguration.CredentialsPath)
			if err != nil {
				return err
			}

			additionalInfo.ApplicationInfo = append(additionalInfo.ApplicationInfo, applicationInfo)

			additionalInfo.IsTasksToBePrepare = true

			taskNames = append(taskNames, &currentTask)

		}

		directoryPath, err := rule.InitRule(ruleName, path, taskNames, additionalInfo)
		if err != nil {
			return err
		}
		additionalInfo.Path = directoryPath

		for i, taskData := range taskNames {
			if tasks[i].Create {
				var supportedLang constants.SupportedLanguage
				supportedLanguage, err := supportedLang.GetSupportedLanguage(taskData.Language)
				if err != nil {
					return err
				}
				taskWithSpecicficLanguage := task.GetTask(*supportedLanguage)

				if cowlibutils.IsFolderExist(filepath.Join(tasks[i].Path, tasks[i].Name)) {
					err := cowlibutils.RemoveChildrensFromFolder(filepath.Join(tasks[i].Path, tasks[i].Name))
					if err != nil {
						return err
					}
				}

				taskWithSpecicficLanguage.InitTask(tasks[i].Name, tasks[i].Path, &vo.TaskInputVO{}, additionalInfo)
			}
		}
	
		additionalInfo.GlobalCatalog = false
	}

	

	return nil
}
