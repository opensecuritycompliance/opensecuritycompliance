package ruleList

import (
	"cowctl/utils"
	"cowlibrary/applications"
	"cowlibrary/constants"
	cowlibrule "cowlibrary/rule"
	cowlibutils "cowlibrary/utils"
	"cowlibrary/vo"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args: cobra.NoArgs,

		Use:   "rule-list",
		Short: "publish rule-list",
		Long:  "publish rule-list",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd)
		},
	}
	return cmd
}

func runE(cmd *cobra.Command) error {
	additionalInfo, err := utils.GetAdditionalInfoFromCmd(cmd)
	if err != nil {
		return err
	}

	ruleListPath := []string{filepath.Join(filepath.Dir(additionalInfo.PolicyCowConfig.PathConfiguration.RulesPath), "ruleList", "*", constants.RuleListYAMLFileName)}
	ruleListName, err := utils.GetValueAsFolderNameFromCmdPromptInCatalogs("Select a ruleList :", true, ruleListPath, utils.ValidateString, additionalInfo)

	if err != nil {
		return err
	}

	if cowlibutils.IsEmpty(ruleListName) {
		return errors.New("rule-list name cannot be empty")
	}
	ruleListFile := filepath.Join(filepath.Dir(additionalInfo.PolicyCowConfig.PathConfiguration.RulesPath), "ruleList", ruleListName, constants.RuleListYAMLFileName)
	ruleListBytes, err := os.ReadFile(ruleListFile)

	if err != nil {
		return fmt.Errorf("failed to read RuleList YAML: %w", err)
	}

	var ruleList vo.RuleListYAML
	if err := yaml.Unmarshal(ruleListBytes, &ruleList); err != nil {
		return fmt.Errorf("invalid RuleList structure: %w", err)
	}

	if ruleList.Spec.PublishApplicationTypeEnabled {

		uniqueApps := make(map[string]*vo.CowNamePointersVO)
		for _, rule := range ruleList.Spec.Rules {
			if strings.ToLower(rule.Catalog) == "globalcatalog" {
				additionalInfo.GlobalCatalog = true
			}
			rulePath := cowlibutils.GetRulePathFromCatalog(additionalInfo, rule.Name)
			if cowlibutils.IsNotValidRulePath(rulePath) {
				return fmt.Errorf("invalid rule path: %s", rulePath)
			}

			inputFile := filepath.Join(rulePath, constants.TaskInputYAMLFile)
			inputBytes, err := os.ReadFile(inputFile)
			if err != nil {
				return fmt.Errorf("failed to read inputs.yaml for rule %s: %w", rule.Name, err)
			}

			var appInfo vo.TaskInputV2
			if err := yaml.Unmarshal(inputBytes, &appInfo); err != nil {
				return fmt.Errorf("invalid inputs.yaml structure for rule %s: %w", rule.Name, err)
			}

			// Collect apps
			if appInfo.UserObject.App != nil {
				uniqueApps[appInfo.UserObject.App.ApplicationName] = &vo.CowNamePointersVO{
					Name: appInfo.UserObject.App.ApplicationName,
				}
			}
			for _, app := range appInfo.UserObject.Apps {
				if app != nil {
					uniqueApps[app.ApplicationName] = &vo.CowNamePointersVO{
						Name: app.ApplicationName,
					}
				}
			}
		}

		fmt.Println("\n⚙️  ApplicationType Publishing")
		fmt.Println(strings.Repeat("─", 50))

		for _, namePointer := range uniqueApps {
			appPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationTypesPath, ruleList.Spec.ApplicationTypeLanguage, namePointer.Name)
			if ruleList.Spec.ApplicationTypeLanguage == "python" {
				appPath = filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationTypesPath, ruleList.Spec.ApplicationTypeLanguage, filepath.Base(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationTypesPath), namePointer.Name)
			}

			if ruleList.Spec.ApplicationTypeOverrideEnabled {
				additionalInfo.CanOverride = true
			}

			if cowlibutils.IsFolderExist(appPath) {
				errorDetails := applications.PublishApplication(namePointer, additionalInfo)
				if len(errorDetails) > 0 {
					if errorDetails[0].Issue == constants.ErrorAppAlreadyPresent {
						fmt.Printf("🟡  %-25s → already published, skipping\n", namePointer.Name)
						continue
					}
					return fmt.Errorf("❌  %-25s → %s", namePointer.Name, errorDetails[0].Issue)
				}
				fmt.Printf("✅ %-20s → published successfully\n", namePointer.Name)
			}
		}
		fmt.Println(strings.Repeat("─", 50))
	}

	fmt.Println("\n📘 Starting Rule publishing process...")
	fmt.Println(strings.Repeat("─", 50))

	for _, rule := range ruleList.Spec.Rules {
		if strings.ToLower(rule.Catalog) == "globalcatalog" {
			additionalInfo.GlobalCatalog = true
		}
		rulesPath := cowlibutils.GetRulePathFromCatalog(additionalInfo, rule.Name)
		if cowlibutils.IsNotValidRulePath(rulesPath) {
			return fmt.Errorf("%s not valid rule path", rulesPath)
		}

		if ruleList.Spec.RuleOverrideEnabled {
			additionalInfo.CanOverride = true
		}
		additionalInfo.RulePublisher = &vo.RulePublisher{}
		isRuleAlreadyPresent, err := cowlibrule.IsRuleAlreadyPresent(rule.Name, additionalInfo)
		if err != nil {
			return err
		}
		if isRuleAlreadyPresent && !ruleList.Spec.RuleOverrideEnabled {
			fmt.Printf("🟡  %-35s → already published, skipping\n", rule.Name)
			continue
		}
		additionalInfo.RuleName = rule.Name
		additionalInfo.ExportFileType = "tar"

		fmt.Printf("🚀  %-35s → Publishing...\n", rule.Name)

		err = cowlibrule.PublishRule(rulesPath, additionalInfo, false)
		if err != nil {
			fmt.Printf("❌  %-35s → %s\n", rule.Name, err.Error())
			break
		}
		fmt.Println(strings.Repeat("·", 50) + "\n")

	}
	return nil

}
