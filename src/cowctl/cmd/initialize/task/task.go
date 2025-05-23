package task

import (
	"cowlibrary/constants"
	task "cowlibrary/task"
	cowlibutils "cowlibrary/utils"
	"cowlibrary/vo"
	"fmt"
	"strconv"

	"os"
	"path/filepath"

	"github.com/kyokomi/emoji"
	"github.com/spf13/cobra"

	"cowctl/utils"
	"cowctl/utils/validationutils"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args: cobra.NoArgs,

		Use:   "task",
		Short: "Initialize the task",
		Long:  "Initialize the task",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd)
		},
	}

	cmd.Flags().String("name", "", "Set your task name")
	cmd.Flags().String("path", "", "path to initalize the task")
	cmd.Flags().String("language", "go", "path to initalize the task")
	cmd.Flags().String("rules-path", "", "path of the rules folder.")
	cmd.Flags().String("tasks-path", "", "path of the tasks.")
	cmd.Flags().String("config-path", "", "path for the configuration file.")
	cmd.Flags().String("exec-path", "", "maintain the history about the executions")
	cmd.Flags().Bool("can-override", false, "task already exists in the system")
	cmd.Flags().String("catalog", "", `use "globalcatalog" to init task in globalcatalog/tasks`)
	cmd.Flags().Bool("binary", false, "whether using cowctl binary")
	cmd.Flags().String("applicationpath", "", "application path")
	return cmd
}

func runE(cmd *cobra.Command) error {

	additionalInfo, err := utils.GetAdditionalInfoFromCmd(cmd)
	if err != nil {
		return err
	}

	taskName := ``
	tasksPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath, "tasks")
	if additionalInfo.GlobalCatalog {
		tasksPath = additionalInfo.PolicyCowConfig.PathConfiguration.TasksPath
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
		// proceed normally
		if cmd.Flags().HasFlags() {
			taskName = utils.GetFlagValueAndResetFlag(cmd, "name", "")
			tasksPath = utils.GetFlagValueAndResetFlag(cmd, "path", tasksPath)
		}

		if cowlibutils.IsNotEmpty(tasksPath) && cowlibutils.IsFolderNotExist(tasksPath) {
			isConfirmed, err := utils.GetConfirmationFromCmdPrompt("Path is not available. Are you going to initialize the folder ?")
			if !isConfirmed || err != nil {
				return err
			}

			err = os.MkdirAll(tasksPath, os.ModePerm)
			if err != nil {
				return err
			}

		}

		taskGetLabelName := "Task Name (only alphabets and numbers and must start with a capital letter)"

		if cowlibutils.IsNotEmpty(taskName) {
			err := validationutils.ValidateAlphaNumeric(taskName)
			if err != nil {
				taskGetLabelName = "Please enter a valid task name(only alphabets and numbers and must start with a capital letter)"
				taskName = ""
			}
		}

		if cowlibutils.IsEmpty(taskName) {
			taskNameFromCmd, err := utils.GetValueAsStrFromCmdPrompt(taskGetLabelName, true, validationutils.ValidateAlphaNumeric)
			if err != nil || cowlibutils.IsEmpty(taskNameFromCmd) {
				return err
			}
			taskName = taskNameFromCmd
		}
		taskPath := filepath.Join(tasksPath, taskName)

		if cowlibutils.IsFolderExist(taskPath) && !additionalInfo.CanOverride {
			if !isDefaultConfigPath && !additionalInfo.CanOverride {
				return fmt.Errorf("The task is already present in the system. To want to re-initialize again, set the 'can-override' flag as true")
			}
			isConfirmed, err := utils.GetConfirmationFromCmdPrompt("Task already presented in the directory. Are you sure you going to re-initialize ?")
			if !isConfirmed || err != nil {
				return err
			}
			err = cowlibutils.RemoveChildrensFromFolder(taskPath)
			if err != nil {
				return err
			}
		}

		currentTask := vo.TaskInputVO{}
		currentTask.TaskName = taskName
		languageFromCmd, err := utils.GetConfirmationFromCmdPromptWithOptions("Enter the programming language for task  python/go (default:go):", "go", []string{"go", "python"})
		if err != nil {
			return err
		}

		currentTask.Language = languageFromCmd
		var supportedLang constants.SupportedLanguage
		supportedLanguage, err := supportedLang.GetSupportedLanguage(currentTask.Language)
		if err != nil {
			return err
		}

		addApplication, err := utils.GetConfirmationFromCmdPrompt("Would you like to add ApplicationType ? ")
		if err != nil {
			return err
		}

		if addApplication {
			selectedAppItem, err := utils.GetApplicationNamesFromCmdPromptInCatalogs("Select the ApplicationType : ", true, []string{additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationTypeConfigPath})
			if err != nil {
				return err
			}

			applicationInfo, err := utils.GetApplicationWithCredential(selectedAppItem.Path, additionalInfo.PolicyCowConfig.PathConfiguration.CredentialTypeConfigPath)
			if err != nil {
				return err
			}

			additionalInfo.ApplicationInfo = append(additionalInfo.ApplicationInfo, applicationInfo)
		}

		taskWithSpecicficLanguage := task.GetTask(*supportedLanguage)
		additionalInfo.IsTasksToBePrepare = true
		taskWithSpecicficLanguage.InitTask(taskName, tasksPath, &vo.TaskInputVO{}, additionalInfo)
		_, err = task.GenerateTaskYAML(taskPath, taskName, additionalInfo)
		if err != nil {
			return err
		}

		emoji.Println(taskName, " Task has been created:smiling_face_with_sunglasses:! you can see your task at: ", filepath.Join(tasksPath, taskName))

		additionalInfo.GlobalCatalog = false
	} else {
		taskName = utils.GetFlagValueAndResetFlag(cmd, "name", "")
		tasksPath = utils.GetFlagValueAndResetFlag(cmd, "path", tasksPath)
		if cowlibutils.IsFolderNotExist(tasksPath) {
			err = os.MkdirAll(tasksPath, os.ModePerm)
			if err != nil {
				return err
			}
		}
		taskPath := filepath.Join(tasksPath, taskName)

		currentTask := vo.TaskInputVO{}
		currentTask.TaskName = taskName

		currentTask.Language = utils.GetFlagValueAndResetFlag(cmd, "language", "go")
		var supportedLang constants.SupportedLanguage
		supportedLanguage, err := supportedLang.GetSupportedLanguage(currentTask.Language)
		if err != nil {
			return err
		}

		applicationpath := utils.GetFlagValueAndResetFlag(cmd, "applicationpath", "")

		if cowlibutils.IsNotEmpty(applicationpath) {
			applicationInfo, err := utils.GetApplicationWithCredential(applicationpath, additionalInfo.PolicyCowConfig.PathConfiguration.CredentialTypeConfigPath)
			if err != nil {
				return err
			}
			additionalInfo.ApplicationInfo = append(additionalInfo.ApplicationInfo, applicationInfo)
		}

		if cowlibutils.IsFolderExist(taskPath) {
			err = cowlibutils.RemoveChildrensFromFolder(taskPath)
			if err != nil {
				return err
			}
		}

		additionalInfo.IsTasksToBePrepare = true

		taskWithSpecicficLanguage := task.GetTask(*supportedLanguage)
		taskWithSpecicficLanguage.InitTask(taskName, tasksPath, &vo.TaskInputVO{}, additionalInfo)

		_, err = task.GenerateTaskYAML(taskPath, taskName, additionalInfo)
		if err != nil {
			return err
		}

	}
	return nil

}
