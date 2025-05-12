package rule

import (
	"cowlibrary/constants"
	rule "cowlibrary/rule"
	cowlibutils "cowlibrary/utils"
	"cowlibrary/vo"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/kyokomi/emoji"
	cp "github.com/otiai10/copy"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"cowctl/utils"
	"cowctl/utils/terminalutils"
	"cowctl/utils/validationutils"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args: cobra.NoArgs,

		Use:   "rule",
		Short: "Execute the rule",
		Long:  "Execute the rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd, false)
		},
	}

	// We can reset the flag by nonPersistentFlag.Changed = false
	cmd.Flags().String("rule-name", "", "path of the rules folder.")
	cmd.Flags().Bool("verbose", false, "display the output of the rules")
	cmd.Flags().String("catalog", "", `set "globalcatalog" to search only globalcatalog/rules`)
	cmd.Flags().String("rules-path", "", "path of the rules folder.")
	cmd.Flags().String("tasks-path", "", "path of the tasks.")
	cmd.Flags().String("synthesizer-path", "", "path for the synthesizer folder.")
	cmd.Flags().String("config-path", "", "path for the configuration file.")
	cmd.Flags().String("rule-group-path", "", "path for the assesments file.")
	cmd.Flags().String("exec-path", "", "maintain the history about the executions")
	cmd.Flags().String("user-inputs", "", "inputs for rule to execute")
	cmd.Flags().Bool("preserve-execution-setup", false, "set up the rule/rule group execution under cowexecutions")

	return cmd
}

func NewRuleGroupCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args: cobra.NoArgs,

		Use:   "rulegroup",
		Short: "Execute the rulegroup",
		Long:  "Execute the rulegroup",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd, true)
		},
	}

	// We can reset the flag by nonPersistentFlag.Changed = false
	cmd.Flags().String("rule-group-name", "", "path of the rules folder.")
	cmd.Flags().Bool("verbose", false, "display the output of the rules")
	cmd.Flags().String("catalog", "", `"globalcatalog" search only globalcatalog/rulegroups`)
	cmd.Flags().String("rules-path", "", "path of the rules folder.")
	cmd.Flags().String("tasks-path", "", "path of the tasks.")
	cmd.Flags().String("synthesizer-path", "", "path for the synthesizer folder.")
	cmd.Flags().String("config-path", "", "path for the configuration file.")
	cmd.Flags().String("rule-group-path", "", "path for the assesments file.")
	cmd.Flags().String("exec-path", "", "maintain the history about the executions")
	cmd.Flags().Bool("preserve-execution-setup", false, "set up the rule/rule group execution under cowexecutions")

	return cmd
}

func runE(cmd *cobra.Command, isRuleGroup bool) error {
	rulesPath, verbose, userInputsJson := ``, false, ""

	additionalInfo, err := utils.GetAdditionalInfoFromCmd(cmd)
	if err != nil {
		return err
	}
	localcatalogPath := additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath

	if cmd.Flags().HasFlags() {
		additionalInfo.RuleName = utils.GetFlagValueAndResetFlag(cmd, "rule-name", "")
		rulesPath = utils.GetFlagValueAndResetFlag(cmd, "rules-path", "")
		additionalInfo.RuleGroupName = utils.GetFlagValueAndResetFlag(cmd, "rule-group-name", "")
		verboseName := utils.GetFlagValueAndResetFlag(cmd, "verbose", "")
		userInputsJson = utils.GetFlagValueAndResetFlag(cmd, "user-inputs", "")
		if cowlibutils.IsNotEmpty(verboseName) {
			verboseAsBool, err := strconv.ParseBool(verboseName)
			if err != nil {
				verbose = false
			} else {
				verbose = verboseAsBool
			}
		}

		if currentFlag := cmd.Flags().Lookup("preserve-execution-setup"); currentFlag != nil && currentFlag.Changed {
			if flagValue := currentFlag.Value.String(); cowlibutils.IsNotEmpty(flagValue) {
				currentFlag.Value.Set("false")
				additionalInfo.PreserveRuleExecutionSetUp, _ = strconv.ParseBool(flagValue)
			}
		}

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
			name, err := utils.GetValueAsFolderNameFromCmdPromptInCatalogs("Select a rulegroup :", true, pathPrefixs, utils.ValidateString, additionalInfo)
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

			ruleYamlPath := filepath.Join(rulesPath, constants.RuleYamlFile)
			ruleSet, err := rule.GetRuleSetFromYAML(ruleYamlPath)
			if err != nil {
				return err
			}
			var taskPaths []string

			if ruleSet != nil && len(ruleSet.Rules) > 0 {
				rule := ruleSet.Rules[0]
				if len(rule.TasksInfo) > 0 {
					taskInfos := make([]*vo.TaskInfo, 0)

					byts, err := json.Marshal(rule.TasksInfo)
					if err != nil {
						return err
					}

					err = json.Unmarshal(byts, &taskInfos)
					if err != nil {
						return err
					}
					for _, task := range taskInfos {
						taskName := strings.NewReplacer("{{", "", "}}", "").Replace(task.TaskGUID)
						taskPaths = append(taskPaths, cowlibutils.GetTaskPathFromCatalog(additionalInfo, name, taskName))
					}

				}
			}
			var taskMetas []vo.PolicyCowTaskVO
			isMetaYaml := true
			for _, taskPath := range taskPaths {
				taskyamlPath := filepath.Join(taskPath, constants.TaskMetaYAMLFileName)
				if cowlibutils.IsFileNotExist(taskyamlPath) {
					isMetaYaml = false
					break
				}
				taskYaml, err := os.ReadFile(taskyamlPath)
				if err != nil {
					return err
				}

				var taskMeta vo.PolicyCowTaskVO
				if err := yaml.Unmarshal(taskYaml, &taskMeta); err != nil {
					return err
				}

				taskMetas = append(taskMetas, taskMeta)
			}

			tempDir := os.TempDir()
			if tempDir == "/tmp" {
				uuid := uuid.New().String()
				tempDir = filepath.Join(tempDir, uuid)
			}
			srcRuleDir := rulesPath
			if cowlibutils.IsNotValidRulePath(rulesPath) {
				srcRuleDir = cowlibutils.GetRuleNameFromAdditionalInfoWithRuleName(additionalInfo.RuleName, additionalInfo)
			}
			tmpRuleDir := filepath.Join(tempDir, additionalInfo.RuleName)
			err = cp.Copy(srcRuleDir, tmpRuleDir)
			if err != nil {
				return err
			}

			if len(ruleSet.Rules[0].RuleIOValues.Inputs) > 0 && isMetaYaml {
				isConfirmed, err := terminalutils.GetConfirmationFromCmdPrompt("Are you going to give the values for userInputs ?")
				if err != nil {
					return err
				}

				if isConfirmed {
					additionalInfo.UpdateUserInputs = true
					var taskInput vo.TaskInput

					inputYAMLFileByts, err := os.ReadFile(filepath.Join(tmpRuleDir, constants.TaskInputYAMLFile))
					if err == nil {
						err = yaml.Unmarshal(inputYAMLFileByts, &taskInput)
						if err != nil {
							return fmt.Errorf("not a valid rule input structure. error :%s", err.Error())
						}

						for key := range ruleSet.Rules[0].RuleIOValues.Inputs {
							if userInputValue, ok := taskInput.UserInputs[key]; ok {
								ruleSet.Rules[0].RuleIOValues.Inputs[key] = userInputValue
							}
						}
						taskInput.UserInputs = ruleSet.Rules[0].RuleIOValues.Inputs
					}

					userInputs := make(map[string]interface{})
					var unmatchedInputs []string
					for inputName := range taskInput.UserInputs {
						var userInput interface{}
						inputMatched := false
						for _, taskMeta := range taskMetas {
							for _, metaInput := range taskMeta.Inputs {
								labelname := fmt.Sprintf("Enter value for %s (current value: %v): ", inputName, ruleSet.Rules[0].RuleIOValues.Inputs[inputName])
								if metaInput.Name == inputName {
									userInput, _ = utils.GetValueAsStrFromCmdPrompt(labelname, true, func(input string) error {
										switch metaInput.DataType {
										case "STRING", "FILE":
											return validationutils.ValidateStringAndFileURL(input)
										case "INT":
											return validationutils.ValidateInt(input)
										}
										return nil
									})
									inputMatched = true
								}
							}
						}
						if !inputMatched {
							unmatchedInputs = append(unmatchedInputs, inputName)
						} else {
							userInputs[inputName] = userInput
						}
					}
					if len(unmatchedInputs) > 0 {
						return fmt.Errorf("inputs not matched with metadata: %v", strings.Join(unmatchedInputs, ", "))
					}

					for inputName, value := range userInputs {
						taskInput.UserInputs[inputName] = value
					}
					taskInputBytes, err := yaml.Marshal(taskInput)
					if err != nil {
						return err
					}
					if err := os.WriteFile(filepath.Join(tmpRuleDir, constants.TaskInputYAMLFile), taskInputBytes, os.ModePerm); err != nil {
						return err
					}
					additionalInfo.TempDirPath = tempDir
				}
			}

			isConfirmed, err := terminalutils.GetConfirmationFromCmdPrompt("Are you going to change the from_date and to_date? ")
			if err != nil {
				return err
			}

			if isConfirmed {
				additionalInfo.UpdateUserInputs = true

				var taskInput vo.TaskInput
				inputYAMLFileByts, err := os.ReadFile(filepath.Join(tmpRuleDir, constants.TaskInputYAMLFile))
				if err == nil {
					err = yaml.Unmarshal(inputYAMLFileByts, &taskInput)
					if err != nil {
						return fmt.Errorf("not a valid rule input structure. error :%s", err.Error())
					}
					f := color.New(color.FgRed, color.Bold)

				GetFromDate:
					fromDate, err := utils.GetValueAsStrFromCmdPrompt("Enter the date for from_date [format: YYYY-MM-DD] or [format: YYYY-MM-DDTHH:mm:ssZ]: ", true, validationutils.ValidateDateTime)
					if err != nil {
						return err
					}
					if cowlibutils.IsNotEmpty(fromDate) {
						if taskInput.FromDate_, err = cowlibutils.ParseDateString(fromDate); err != nil {
							f.Println("Invalid from_date format. Error:", err)
							goto GetFromDate
						}
					}

				GetToDate:
					toDate, err := utils.GetValueAsStrFromCmdPrompt("Enter the date for to_date [format: YYYY-MM-DD] or [format: YYYY-MM-DDTHH:mm:ssZ]: ", true, validationutils.ValidateDateTime)
					if err != nil {
						return err
					}
					if cowlibutils.IsNotEmpty(toDate) {
						if taskInput.ToDate_, err = cowlibutils.ParseDateString(toDate); err != nil {
							f.Println("Invalid to_date format. Error:", err)
							goto GetToDate
						}
						if taskInput.ToDate_.Before(taskInput.FromDate_) {
							f.Println("Invalid date: to_date cannot be earlier than from_date")
							goto GetToDate
						}
					}

					taskInputBytes, err := yaml.Marshal(taskInput)
					if err != nil {
						return err
					}

					if err := os.WriteFile(filepath.Join(tmpRuleDir, constants.TaskInputYAMLFile), taskInputBytes, os.ModePerm); err != nil {
						return err
					}
					additionalInfo.TempDirPath = tempDir
				}
			}
		} else {
			if cowlibutils.IsNotEmpty(userInputsJson) {
				var userInputs map[string]interface{}
				if err := json.Unmarshal([]byte(userInputsJson), &userInputs); err != nil {
					return fmt.Errorf("failed to parse user inputs JSON: %w", err)
				}

				tempDir := os.TempDir()
				if tempDir == "/tmp" {
					uuid := uuid.New().String()
					tempDir = filepath.Join(tempDir, uuid)
				}
				srcRuleDir := rulesPath
				if cowlibutils.IsNotValidRulePath(rulesPath) {
					srcRuleDir = cowlibutils.GetRuleNameFromAdditionalInfoWithRuleName(additionalInfo.RuleName, additionalInfo)
				}
				tmpRuleDir := filepath.Join(tempDir, additionalInfo.RuleName)
				err = cp.Copy(srcRuleDir, tmpRuleDir)
				if err != nil {
					return err
				}
				var taskInput vo.TaskInput

				inputYAMLFileByts, err := os.ReadFile(filepath.Join(tmpRuleDir, constants.TaskInputYAMLFile))
				if err != nil {
					return fmt.Errorf("failed to read inputs.yaml: %w", err)
				}
				if err := yaml.Unmarshal(inputYAMLFileByts, &taskInput); err != nil {
					return fmt.Errorf("failed to parse inputs.yaml: %w", err)
				}
				for key, value := range userInputs {
					if _, exists := taskInput.UserInputs[key]; exists {
						taskInput.UserInputs[key] = value
					}
				}

				if fromDate, exists := userInputs["fromDate"]; exists {
					parsedFromDate, err := cowlibutils.ParseDateString(fromDate.(string))
					if err != nil {
						return fmt.Errorf("Invalid fromDate format: %v\n", err)
					}
					taskInput.FromDate_ = parsedFromDate
				}
				if toDate, exists := userInputs["toDate"]; exists {
					parsedToDate, err := cowlibutils.ParseDateString(toDate.(string))
					if err != nil {
						return fmt.Errorf("Invalid fromDate format: %v\n", err)
					}
					taskInput.ToDate_ = parsedToDate
				}
				additionalInfo.UpdateUserInputs = true
				updatedYAML, err := yaml.Marshal(taskInput)
				if err != nil {
					return fmt.Errorf("failed to marshal updated inputs.yaml: %w", err)
				}
				if err := os.WriteFile(filepath.Join(tmpRuleDir, constants.TaskInputYAMLFile), updatedYAML, os.ModePerm); err != nil {
					return fmt.Errorf("failed to write updated inputs.yaml: %w", err)
				}
				additionalInfo.TempDirPath = tempDir
			}
		}
	}

	err = rule.ExecuteRule(rulesPath, "", make([]string, 0), []string{""}, verbose, additionalInfo)

	if err == nil {
		if additionalInfo.ErrorOccured {
			emoji.Println("Execution completed with errors :crying_face:!")
		} else {
			emoji.Println("Execution completed:smiling_face_with_sunglasses:!")
		}
	}

	if additionalInfo.PreserveRuleExecutionSetUp {
		d := color.New(color.BgHiGreen, color.Bold)
		d.Println("We have saved the configured rule set for you in the 'cowexecutions/rules' folder.")
	}

	if err == nil {
		d := color.New(color.FgCyan, color.Bold)
		d.Println("The execution log can be located in the 'cowexecutions/execution.ndjson' file, with the most recent run log appearing on the last line.")
	}

	additionalInfo.GlobalCatalog = false

	return err

}
