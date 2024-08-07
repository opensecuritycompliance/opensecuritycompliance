package rule

import (
	"github.com/spf13/cobra"

	"cowctl/utils"
	task "cowlibrary/task"
	cowutils "cowlibrary/utils"

	"github.com/dmnlk/stringUtils"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args: cobra.NoArgs,

		Use:   "task",
		Short: "Prepare the task",
		Long:  "Prepare the task by filling the missing files for execution",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd)
		},
	}

	cmd.Flags().String("config-path", "", "path for the configuration file.")
	cmd.Flags().StringP("name", "", "", "your rule name")
	return cmd
}

func runE(cmd *cobra.Command) error {
	taskPath := ``
	additionalInfo, err := utils.GetAdditionalInfoFromCmd(cmd)
	if err != nil {
		return err
	}

	if cmd.Flags().HasFlags() {

		if taskPathFlag := cmd.Flags().Lookup("path"); taskPathFlag != nil {
			taskPath = taskPathFlag.Value.String()
		}

	}

	if stringUtils.IsEmpty(taskPath) {
		taskPathFromCmd, err := utils.GetValueAsStrFromCmdPrompt("Task Path", true, utils.ValidateString)
		if err != nil {
			return err
		}
		taskPath = taskPathFromCmd
	}

	suppportedLanguage := cowutils.GetTaskLanguage(taskPath)

	taskWithSpecicficLanguage := task.GetTask(suppportedLanguage)

	return taskWithSpecicficLanguage.PrepareTask(taskPath, additionalInfo)

}
