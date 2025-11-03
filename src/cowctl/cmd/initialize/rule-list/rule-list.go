package ruleList

import (
	"cowctl/utils/multiselect"
	"cowctl/utils/validationutils"
	"cowlibrary/constants"
	cowlibutils "cowlibrary/utils"
	"cowlibrary/vo"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cowctl/utils"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args: cobra.NoArgs,

		Use:   "rule-list",
		Short: "Initialize the rule-list",
		Long:  "Initialize the rule-list",
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

	ruleListNameFromCmd, err := utils.GetValueAsStrFromCmdPrompt("Enter the RuleList name: ", true, validationutils.ValidateAlphaNumeric)
	if err != nil || cowlibutils.IsEmpty(ruleListNameFromCmd) {
		return err
	}
	rulesPath := ``
	localcatalogPath := additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath
	globalCatalogPath := filepath.Dir(additionalInfo.PolicyCowConfig.PathConfiguration.RulesPath)

	pathPrefixes := []string{filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.RulesPath, "*", "rule.json"),
		filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.RulesPath, "*", "rule.yaml")}
	if cowlibutils.IsEmpty(rulesPath) {
		if !additionalInfo.GlobalCatalog {
			pathPrefixes = append(pathPrefixes, filepath.Join(localcatalogPath, "rules", "*", "rule.json"))
			pathPrefixes = append(pathPrefixes, filepath.Join(localcatalogPath, "rules", "*", "rule.yaml"))
			pathPrefixes = append(pathPrefixes, filepath.Join(localcatalogPath, "*", "rules", "*", "rule.json"))
			pathPrefixes = append(pathPrefixes, filepath.Join(localcatalogPath, "*", "rules", "*", "rule.yaml"))
		}
	}

	var ruleOptions []multiselect.MultiSelectItem
	for _, pattern := range pathPrefixes {
		matches, _ := filepath.Glob(pattern)
		for _, path := range matches {
			name := filepath.Base(filepath.Dir(path))
			desc := "globalcatalog"
			if strings.Contains(path, "localcatalog") {
				desc = "localcatalog"
			}
			ruleOptions = append(ruleOptions, multiselect.MultiSelectItem{
				Title:       fmt.Sprintf("%s - [%s]", name, desc),
				Description: desc,
			})
		}
	}

	selectedRules, err := multiselect.RunMultiSelect("Select rules:", ruleOptions)
	if err != nil {
		return err
	}

	if len(selectedRules) == 0 {
		return errors.New("no rules selected")
	}

	ruleOverrideEnabled, err := utils.GetConfirmationFromCmdPrompt("Do you want to allow overriding rules if they already exist?")
	if err != nil {
		return err
	}

	publishApplicationEnabled, err := utils.GetConfirmationFromCmdPrompt("Do you want to publish the ApplicationType present in the rules?")
	if err != nil {
		return err
	}

	var applicationTypeLanguage string
	var applicationTypeOverrideEnabled bool
	if publishApplicationEnabled {
		applicationTypeLanguage, err = utils.GetConfirmationFromCmdPromptWithOptions("Which language do you want to publish the ApplicationType in? (Python/Go): ", "", []string{"go", "python"})
		if err != nil {
			return err
		}
		applicationTypeOverrideEnabled, err = utils.GetConfirmationFromCmdPrompt("Do you want to override existing ApplicationType implementations if they exist?")
		if err != nil {
			return err
		}
	}

	ruleListDir := filepath.Join(globalCatalogPath, "rulelist", ruleListNameFromCmd)
	if _, err := os.Stat(ruleListDir); os.IsNotExist(err) {
		if err := os.MkdirAll(ruleListDir, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create directory: %v", err)
		}
	}

	var rules []vo.RuleEntry
	for _, titleWithCatalog := range selectedRules {
		title := strings.Split(titleWithCatalog, " [")[0]
		title = strings.TrimSuffix(title, "-")
		title = strings.TrimSpace(title)
		catalog := "globalcatalog"
		if strings.Contains(titleWithCatalog, "localcatalog") {
			catalog = "localcatalog"
		}
		rules = append(rules, vo.RuleEntry{Name: title, Catalog: catalog})
	}

	ruleList := vo.RuleListYAML{
		Kind: "RuleList",
		Metadata: vo.RuleListMetadata{
			Name:    ruleListNameFromCmd,
			Purpose: ruleListNameFromCmd,
		},
		Spec: vo.RuleListSpec{
			RuleOverrideEnabled:            ruleOverrideEnabled,
			PublishApplicationTypeEnabled:  publishApplicationEnabled,
			ApplicationTypeLanguage:        applicationTypeLanguage,
			ApplicationTypeOverrideEnabled: applicationTypeOverrideEnabled,
			Rules:                          rules,
		},
	}

	data, err := yaml.Marshal(&ruleList)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %v", err)
	}

	ruleListFile := filepath.Join(ruleListDir, constants.RuleListYAMLFileName)
	if err := os.WriteFile(ruleListFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write YAML file: %v", err)
	}

	fmt.Printf("\n✅ Created rulelist.yaml at %s\n", ruleListFile)
	return nil
}
