package rule

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"cowctl/utils"
	rule "cowlibrary/rule"

	"github.com/dmnlk/stringUtils"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args: cobra.NoArgs,

		Use:   "rule",
		Short: "Prepare the rule",
		Long:  "Prepare the rule for execution",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd)
		},
	}

	cmd.Flags().StringP("name", "", "", "your rule name")
	cmd.Flags().Bool("prepare_tasks_too", true, "prepare the tasks too")
	cmd.Flags().String("rules-path", "", "path of the rules folder.")
	cmd.Flags().String("tasks-path", "", "path of the tasks.")
	cmd.Flags().String("config-path", "", "path for the configuration file.")
	return cmd
}

func runE(cmd *cobra.Command) error {

	additionalInfo, err := utils.GetAdditionalInfoFromCmd(cmd)
	if err != nil {
		return err
	}
	rulePath, ruleName, ruleExp, isTasksToBePrepare := additionalInfo.PolicyCowConfig.PathConfiguration.RulesPath, ``, ``, true

	if cmd.Flags().HasFlags() {

		if ruleNameFlag := cmd.Flags().Lookup("name"); ruleNameFlag != nil {
			ruleName = ruleNameFlag.Value.String()
		}

		if rulePathFlag := cmd.Flags().Lookup("prepare_tasks_too"); rulePathFlag != nil {
			isTasksToBePrepare = rulePathFlag.Value.String() == "true"
		}

	}

	if stringUtils.IsEmpty(ruleName) {
		ruleName, err = utils.GetValueAsStrFromCmdPrompt("Rule Name", true, utils.ValidateString)
		if err != nil {
			return err
		}

		if stringUtils.IsEmpty(ruleName) {
			return errors.New("rule name cannot be empty")
		}

	}

	rulePath = filepath.Join(rulePath, ruleName)

	if stringUtils.IsNotEmpty(rulePath) {
		fileInfo, err := os.Stat(rulePath)
		if os.IsNotExist(err) || fileInfo == nil || !fileInfo.IsDir() {
			pathFromCmd, err := utils.GetValueAsFilePathFromCmdPrompt("Enter a valid file path", true, utils.ValidateFilePath)
			if err != nil || stringUtils.IsEmpty(pathFromCmd) {
				return err
			}
			rulePath = pathFromCmd

		}
	}

	return rule.PrepareRule(rulePath, ruleExp, []string{}, []string{}, isTasksToBePrepare, additionalInfo)

}
