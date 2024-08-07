package rule

import (
	"cowlibrary/constants"
	rule "cowlibrary/rule"
	cowlibutils "cowlibrary/utils"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dmnlk/stringUtils"
	"github.com/kyokomi/emoji"
	"github.com/spf13/cobra"

	"cowctl/utils"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args: cobra.NoArgs,

		Use:   "rule",
		Short: "Export the rule",
		Long:  "Export the rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd, false)
		},
	}

	// We can reset the flag by nonPersistentFlag.Changed = false

	cmd.Flags().String("rules-path", "", "path of the rules folder.")
	cmd.Flags().String("rule-name", "", "rule name.")
	cmd.Flags().String("downloads-path", "", "path of the downloads folder.")
	cmd.Flags().String("tasks-path", "", "path of the tasks.")
	cmd.Flags().String("config-path", "", "path for the configuration file.")
	cmd.Flags().String("exec-path", "", "maintain the history about the executions")
	cmd.Flags().String("export-file-type", "tar", "export file type(zip/tar)")
	cmd.Flags().String("catalog", "", "search in globalcatalog/rules only for the rule")

	return cmd
}

// NewRuleGroupCommand returns a new cobra.Command for initialize the rule
func NewRuleGroupCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "rulegroup",
		Short: "Export the rulegroup",
		Long:  "Export the rulegroup",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd, true)
		},
	}

	// We can reset the flag by nonPersistentFlag.Changed = false
	cmd.Flags().String("rules-path", "", "path of the rules folder.")
	cmd.Flags().String("rule-group-name", "", "name of the rules group")
	cmd.Flags().String("rule-group-path", "", "path of the rules hroup.")
	cmd.Flags().String("downloads-path", "", "path of the downloads folder.")
	cmd.Flags().String("tasks-path", "", "path of the tasks.")
	cmd.Flags().String("config-path", "", "path for the configuration file.")
	cmd.Flags().String("exec-path", "", "maintain the history about the executions")
	cmd.Flags().String("export-file-type", "tar", "export file type(zip/tar)")
	cmd.Flags().String("catalog", "", "search in globalcatalog/rulegroups only for the rulegroups")

	return cmd
}

func runE(cmd *cobra.Command, isRuleGroup bool) error {
	additionalInfo, err := utils.GetAdditionalInfoFromCmd(cmd)
	if err != nil {
		return err
	}
	localcatalogPath := additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath

	rulesPath := ``
	downloadsPath := additionalInfo.PolicyCowConfig.PathConfiguration.DownloadsPath
	if cmd.Flags().HasFlags() {
		rulesPath = utils.GetFlagValueAndResetFlag(cmd, "path", rulesPath)
		additionalInfo.RuleName = utils.GetFlagValueAndResetFlag(cmd, "rule-name", "")
		additionalInfo.RuleGroupName = utils.GetFlagValueAndResetFlag(cmd, "rule-group-name", "")
		additionalInfo.DownloadsPath = utils.GetFlagValueAndResetFlag(cmd, "downloads-path", downloadsPath)
		additionalInfo.ExportFileType = utils.GetFlagValueAndResetFlag(cmd, "export-file-type", "tar")

	}

	if !utils.IsValidExportFileType(additionalInfo.ExportFileType) {
		exportFileType, err := utils.GetConfirmationFromCmdPromptWithOptions("not a valid file type to export. Choose the type to provide the file type(default:tar):", "tar", []string{"tar", "zip"})
		if err != nil {
			return err
		}
		additionalInfo.ExportFileType = exportFileType
	}

	if isRuleGroup {
		if cowlibutils.IsEmpty(additionalInfo.RuleGroupName) {
			pathPrefixs := []string{
				filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.RuleGroupPath, "*", "rules_dependency.json")}

			pathPrefixs = append(pathPrefixs, filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.RuleGroupPath, "*", constants.RuleGroupYAMLFileName))

			if !additionalInfo.GlobalCatalog {
				pathPrefixs = append(pathPrefixs, filepath.Join(localcatalogPath, "rulegroups", "*", "rules_dependency.json"))
				pathPrefixs = append(pathPrefixs, filepath.Join(localcatalogPath, "*", "rulegroups", "*", "rules_dependency.json"))
				pathPrefixs = append(pathPrefixs, filepath.Join(localcatalogPath, "rulegroups", "*", constants.RuleGroupYAMLFileName))
				pathPrefixs = append(pathPrefixs, filepath.Join(localcatalogPath, "*", "rulegroups", "*", constants.RuleGroupYAMLFileName))
			}

			name, err := utils.GetValueAsFolderNameFromCmdPromptInCatalogs("Select a rule group :", true, pathPrefixs, utils.ValidateString, additionalInfo)

			if err != nil {
				return err
			}
			rulesPath = cowlibutils.GetRuleGroupPathFromCatalog(additionalInfo, name)
			if !cowlibutils.IsRulesDependencyFolder(rulesPath) {
				return fmt.Errorf("not a valid path. %s", rulesPath)
			}
			additionalInfo.RuleGroupName = name
		}
	} else {

		if cowlibutils.IsEmpty(additionalInfo.RuleName) {
			pathPrefixs := []string{
				filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.RulesPath, "*", "rule.json"),
				filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.RulesPath, "*", "rule.yaml")}
			if !additionalInfo.GlobalCatalog {
				pathPrefixs = append(pathPrefixs, filepath.Join(localcatalogPath, "rules", "*", "rule.json"))
				pathPrefixs = append(pathPrefixs, filepath.Join(localcatalogPath, "rules", "*", "rule.yaml"))
				pathPrefixs = append(pathPrefixs, filepath.Join(localcatalogPath, "*", "rules", "*", "rule.json"))
				pathPrefixs = append(pathPrefixs, filepath.Join(localcatalogPath, "*", "rules", "*", "rule.yaml"))
			}

			name, err := utils.GetValueAsFolderNameFromCmdPromptInCatalogs("Select a rule :", true, pathPrefixs, utils.ValidateString, additionalInfo)
			if err != nil {
				return err
			}
			rulesPath = cowlibutils.GetRulePathFromCatalog(additionalInfo, name)

			if cowlibutils.IsNotValidRulePath(rulesPath) {
				return fmt.Errorf("not a valid path. %s ", rulesPath)
			}
			additionalInfo.RuleName = name
		}

	}

	if cowlibutils.IsNotEmpty(rulesPath) {
		fileInfo, err := os.Stat(rulesPath)
		if os.IsNotExist(err) || fileInfo == nil || !fileInfo.IsDir() {
			pathFromCmd, err := utils.GetValueAsFilePathFromCmdPrompt("Enter a valid file path", true, utils.ValidateFilePath)
			if err != nil || cowlibutils.IsEmpty(pathFromCmd) {
				return err
			}
			rulesPath = pathFromCmd

		}
	}

	fileName := additionalInfo.RuleName

	if stringUtils.IsEmpty(fileName) {
		fileName = additionalInfo.RuleGroupName
	}

	if additionalInfo.ExportFileType == "tar" {
		if !strings.HasSuffix(fileName, ".tar") {
			fileName += ".tar"
		}
	} else {
		if !strings.HasSuffix(fileName, ".zip") {
			fileName += ".zip"
		}
	}

	exportRulePath := filepath.Join(additionalInfo.DownloadsPath, fileName)

	if cowlibutils.IsFileExist(exportRulePath) {
		isConfirmed, err := utils.GetConfirmationFromCmdPrompt("A file for the same rule has already been exported to the directory.\nAre you going to export again ?")
		if !isConfirmed || err != nil {
			return err
		}

		err = os.Remove(exportRulePath)
		if err != nil {
			return err
		}

	}

	_, err = rule.ExportRule(rulesPath, additionalInfo)

	if err == nil {
		emoji.Println("Rule has been exported:smiling_face_with_sunglasses:!:rocket:")
	}

	return err

}
