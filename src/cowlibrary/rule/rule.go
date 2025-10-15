package rule

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"maps"

	"github.com/briandowns/spinner"
	"github.com/dmnlk/stringUtils"
	topo "github.com/fako1024/topo"
	"github.com/fatih/color"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/iancoleman/strcase"
	"github.com/kyokomi/emoji"
	"github.com/minio/minio-go/v7"
	tablewriter "github.com/olekukonko/tablewriter"
	"github.com/otiai10/copy"
	cp "github.com/otiai10/copy"
	progressbar "github.com/schollz/progressbar/v3"
	"gopkg.in/yaml.v2"

	cowStorage "applicationtypes/minio"
	constants "cowlibrary/constants"
	"cowlibrary/executions"
	"cowlibrary/storage"
	"cowlibrary/task"
	"cowlibrary/utils"
	"cowlibrary/vo"
	cowvo "cowlibrary/vo"
)

var pythonPackages sync.Map

func InitRule(ruleName, path string, tasks []*vo.TaskInputVO, additionalInfo *vo.AdditionalInfo) (string, error) {
	// m:TO DO Revisit
	directoryPath, err := utils.GetRulePath(path, ruleName)
	if err != nil {
		return "", errors.New("not a valid path")
	}
	_, err = os.Stat(directoryPath)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(directoryPath, os.ModePerm); err != nil {
			return "", errors.New("not a valid path")
		}
	}

	if err := writeRuleYaml(directoryPath, tasks, additionalInfo); err != nil {
		return "", err
	}

	return directoryPath, nil
}

func writeRuleYaml(directoryPath string, taskInfos []*vo.TaskInputVO, additionalInfo *vo.AdditionalInfo) error {
	ruleYAML := constants.RuleYAML

	var rule vo.RuleYAMLVO
	err := yaml.Unmarshal([]byte(ruleYAML), &rule)
	if err != nil {
		return fmt.Errorf("error in unmarshalling rule yaml,error:%S", err)
	}
	rule.Meta.Name = strcase.ToCamel(filepath.Base(directoryPath))

	if additionalInfo.PrimaryApplicationInfo != nil {
		rule.Meta.Labels = additionalInfo.PrimaryApplicationInfo.App.Meta.Labels
		rule.Meta.Annotations = additionalInfo.PrimaryApplicationInfo.App.Meta.Annotations
	}
	// rule.Meta.Labels.App = GetAppLabels(additionalInfo.ApplicationInfo.App.Meta.Labels)
	if len(taskInfos) > 0 {

		var tasks []*vo.TaskVO
		for i, taskInfo := range taskInfos {
			var appTags map[string][]string

			if i < len(additionalInfo.ApplicationInfo) && additionalInfo.ApplicationInfo[i] != nil {
				appInfo := additionalInfo.ApplicationInfo[i]
				appTags = appInfo.App.AppTags
			}
			if utils.IsEmpty(taskInfo.Alias) {
				taskInfo.Alias = "t" + strconv.Itoa(i+1)
			}
			if utils.IsEmpty(taskInfo.Description) {
				taskInfo.Description = "Detailed info about the task"
			}
			tasks = append(tasks, &vo.TaskVO{
				Name:           strcase.ToCamel(taskInfo.TaskName),
				Purpose:        "Purpose of the task",
				Description:    taskInfo.Description,
				Type:           "task",
				AppTags:        appTags,
				Alias:          taskInfo.Alias,
				ValidationCURL: taskInfo.ValidationCURL,
			})
		}

		rule.Spec.Tasks = tasks

	}

	if additionalInfo.RuleYAMLVO != nil && additionalInfo.RuleYAMLVO.Spec != nil {

		if additionalInfo.RuleYAMLVO.Meta != nil {
			rule.Meta.Description = additionalInfo.RuleYAMLVO.Meta.Description
			rule.Meta.Purpose = additionalInfo.RuleYAMLVO.Meta.Purpose
		}

		if additionalInfo.RuleYAMLVO.Meta != nil {
			rule.Meta.Annotations = additionalInfo.RuleYAMLVO.Meta.Annotations
			// if len(additionalInfo.RuleYAMLVO.Meta.Annotations) > 0 {
			// 	for annotation, tags := range additionalInfo.RuleYAMLVO.Meta.Annotations {
			// 		rule.Meta.Annotations[annotation] = tags
			// 	}
			// }
			if len(additionalInfo.RuleYAMLVO.Meta.Labels) > 0 {
				if len(rule.Meta.Labels) == 0 {
					rule.Meta.Labels = make(map[string][]string, 0)
				}
				for annotation, tags := range additionalInfo.RuleYAMLVO.Meta.Labels {
					rule.Meta.Labels[annotation] = tags
				}
			}
		}

		if len(additionalInfo.RuleYAMLVO.Spec.IoMap) > 0 {
			rule.Spec.IoMap = additionalInfo.RuleYAMLVO.Spec.IoMap
		}

		rule.Spec.Input = additionalInfo.RuleYAMLVO.Spec.Input

		for _, input := range additionalInfo.RuleYAMLVO.Spec.InputsMeta__ {
			input.ShowField = true
			input.Required = true
		}
		rule.Spec.InputsMeta__ = additionalInfo.RuleYAMLVO.Spec.InputsMeta__
		// commenting rule input not mapped filter for nocode auto save
		// ruleIoMapInfo, _ := utils.GetRuleIOMapInfo(rule.Spec.IoMap)
		// inputs := make(map[string]bool)
		// for _, val := range ruleIoMapInfo.InputVaribales {
		// 	inputs[val] = true
		// }

		// var usedInputsMeta []*vo.RuleUserInputVO
		// usedInputs := make(map[string]interface{})

		// for _, inputMeta := range rule.Spec.InputsMeta__ {
		// 	if _, exists := inputs[inputMeta.Name]; exists {
		// 		usedInputsMeta = append(usedInputsMeta, inputMeta)
		// 		usedInputs[inputMeta.Name] = rule.Spec.Input[inputMeta.Name]
		// 	}
		// }

		// rule.Spec.InputsMeta__ = usedInputsMeta
		// rule.Spec.Input = usedInputs

	}

	ruleByts, err := yaml.Marshal(rule)
	if err != nil {
		return err
	}

	err = os.WriteFile(directoryPath+string(os.PathSeparator)+constants.RuleYamlFile, ruleByts, os.ModePerm)
	if err != nil {
		return err
	}

	taskPath := directoryPath
	_, err = task.GenerateTaskYAML(taskPath, rule.Meta.Name, additionalInfo)
	return err
}

func GetAppLabels(labels map[string][]string) []string {
	appLabels := make([]string, 0)
	for _, label := range labels {
		appLabels = append(appLabels, label...)
	}
	return appLabels
}

// func writeRuleJSON(directoryPath string, taskInfos []*vo.TaskInputVO) error {
// 	ruleJSON := constants.RuleJSON

// 	ruleSet := &vo.RuleSet{}

// 	err := json.Unmarshal([]byte(ruleJSON), ruleSet)
// 	if err != nil {
// 		return err
// 	}

// 	if len(ruleSet.Rules) > 0 && len(taskInfos) > 0 {

// 		tasks := make([]interface{}, 0)
// 		taskRefMap := make([]*vo.RefStruct, 0)

// 		for i, taskInfo := range taskInfos {
// 			tasks = append(tasks, TaskBase{
// 				Purpose:     "Purpose of the task",
// 				Description: "Detailed info about the task",
// 				Type:        "task",
// 				Aliasref:    "t" + strconv.Itoa(i+1),
// 				TaskGUID:    "{{" + strcase.ToCamel(taskInfo.TaskName) + "}}",
// 			})

// 			if len(taskInfo.RefMaps) > 0 {
// 				taskRefMap = append(taskRefMap, taskInfo.RefMaps...)
// 			}
// 		}

// 		ruleSet.Rules[0].TasksInfo = tasks
// 		if len(taskRefMap) > 0 {
// 			ruleSet.Rules[0].RefMaps = append(ruleSet.Rules[0].RefMaps, taskRefMap...)
// 		}
// 	}

// 	ruleByts, err := json.MarshalIndent(ruleSet, "", " ")
// 	if err != nil {
// 		return err
// 	}

// 	if err := os.WriteFile(directoryPath+string(os.PathSeparator)+constants.RuleFile, ruleByts, os.ModePerm); err != nil {
// 		return err
// 	}

// 	return nil

// }

func ExecuteRule(path, ruleExp string, includeRules, excludeRules []string, isVerbose bool, additionalInfo *vo.AdditionalInfo) error {

	if !utils.IsMinioCredAvailable() {
		return errors.New("the 'minio' credentials are not provided. Kindly include them in the environment file and restart the server")
	}

	ruleOutputs, err := ExecuteRulesAndReturnOutputs(path, ruleExp, includeRules, excludeRules, isVerbose, additionalInfo)
	if err != nil {
		return err
	}

	if len(ruleOutputs) > 0 {
		DrawSummaryTable(ruleOutputs, additionalInfo)
	}

	return err

}

func ExecuteRulesAndReturnOutputs(filePath, ruleExp string, includeRules, excludeRules []string, isVerbose bool, additionalInfo *vo.AdditionalInfo) (ruleOutputArr []*vo.RuleOutputs, err error) {

	directoryPath := ``
	if stringUtils.IsEmpty(additionalInfo.ExecutionID) {
		uuid_, err := uuid.NewUUID()
		if err != nil {
			return nil, err
		}
		additionalInfo.ExecutionID = uuid_.String()
	}
	if stringUtils.IsEmpty(filePath) {
		additionalInfo.PreserveRuleExecutionSetUp = true
		if utils.IsNotEmpty(additionalInfo.RuleName) {
			filePath = utils.GetRulePathFromCatalog(additionalInfo, additionalInfo.RuleName)
			if utils.IsNotValidRulePath(filePath) {
				return nil, errors.New("not a valid rule,check rule folder")
			}
		} else if utils.IsNotEmpty(additionalInfo.RuleGroupName) {
			filePath = utils.GetRuleGroupPathFromCatalog(additionalInfo, additionalInfo.RuleGroupName)
		} else {
			wd, err := os.Getwd()
			if err != nil {
				return ruleOutputArr, err
			}
			filePath = wd
		}

	}
	if utils.IsFolderExist(filePath) {
		filePath = strings.TrimSuffix(filePath, "/")
		directoryPath = filePath
	} else {
		return ruleOutputArr, fmt.Errorf("%s not a valid path", filePath)

	}

	isToBeIgnore := func(path string, parentPaths []string) bool {
		for _, val := range parentPaths {
			if strings.HasPrefix(path, val) {
				return true
			}
		}
		return false
	}

	pathsToBeIgnore := []string{}
	ruleOutputs := make(map[string]*vo.RuleOutputs)
	ruleOutputsHelperArr := make([]*vo.RuleOutputs, 0)
	ruleNameAndAliasInfo := make(map[string]string, 0)

	rulesCount, err := utils.FetchRuleCountInFolder(directoryPath)
	if err != nil {
		return ruleOutputArr, err
	}

	if rulesCount == 0 {
		return ruleOutputArr, errors.New("No rules available to execute")
	}

	bar := fetchProgressBar(rulesCount)

	bar.Describe("Analysing rules...")

	ruleExecutions := &vo.CowRuleExecutions{}

	taskExecutions := make(map[string]map[string]map[string]interface{}, 0)

	var tempDir string
	if additionalInfo.UpdateUserInputs {
		tempDir = additionalInfo.TempDirPath
	} else {
		tempDir = os.TempDir()
		if tempDir == "/tmp" {
			uuid := uuid.New().String()
			tempDir = filepath.Join(tempDir, uuid)
		}
	}

	defer os.RemoveAll(tempDir)

	err = filepath.WalkDir(directoryPath, func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !isToBeIgnore(path, pathsToBeIgnore) && info.IsDir() {
			if isRulesDependencyFolder(path) {
				ruleExecutions.Type = constants.ExecutionTypeRuleGroup
				pathsToBeIgnore = append(pathsToBeIgnore, path)
				err = handleDependecyFlow(path, "Executing", ruleOutputs, bar, ruleNameAndAliasInfo, isVerbose, true, additionalInfo, taskExecutions, tempDir, false, &ruleOutputsHelperArr)
				if err != nil {
					return err
				}
			} else if isValidRulePath(path) {
				ruleExecutions.Type = constants.ExecutionTypeRule
				ruleNameAndAliasInfo[info.Name()] = info.Name()
				ruleOutputs[info.Name()] = &vo.RuleOutputs{RuleName: info.Name()}
				err := executeRuleHelper(path, info.Name(), ruleOutputs, &vo.RuleDependency{}, ruleNameAndAliasInfo, bar, isVerbose, additionalInfo, taskExecutions, tempDir, true, &ruleOutputsHelperArr)

				if err != nil {
					return err
				}

			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	bar.Describe("finished")

	ruleExecutions.RunDetails = taskExecutions

	var executions *executions.RuleExecutions

	ruleExecutions.ExecutionID = additionalInfo.ExecutionID

	ruleOutputArr = ruleOutputsHelperArr

	if len(ruleOutputsHelperArr) == 0 {
		for _, ruleOutput := range ruleOutputs {
			ruleOutputArr = append(ruleOutputArr, ruleOutput)
		}
	}

	ruleExecutions.RuleOutputs = ruleOutputArr

	err = executions.Create(ruleExecutions, additionalInfo, "")
	if err != nil {
		return nil, err
	}

	pathByts, err := json.Marshal(additionalInfo.PolicyCowConfig.PathConfiguration)
	if err == nil {
		os.Setenv("POLICY_COW_CONFIGS", string(pathByts))
		os.Setenv("IS_POLICY_COW_FLOW", "true")
	}

	err = ExecuteSynthesizers(ruleExecutions, additionalInfo, tempDir)
	if err != nil {
		return nil, err
	}

	ReplaceExecutionData(ruleExecutions, additionalInfo)

	return ruleOutputArr, err

}

func ReplaceExecutionData(ruleExecutions *vo.CowRuleExecutions, additionalInfo *vo.AdditionalInfo) {

	executionPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.ExecutionPath, constants.ExecutionsFile)

	if byts, err := os.ReadFile(executionPath); err == nil {

		if err == nil {
			lines := strings.Split(string(byts), "\n")

			ruleByts, err := json.Marshal(ruleExecutions)
			if err == nil {
				for i, line := range lines {
					if strings.Contains(line, ruleExecutions.ExecutionID) {
						lines[i] = string(ruleByts)
					}
				}
				output := strings.Join(lines, "\n")
				err = os.WriteFile(executionPath, []byte(output), 0644)
				if err != nil {
					log.Fatalln(err)
				}
			}

		}
	}

}

func FetchSynthesizerCountForExecution(ruleExecutions *vo.CowRuleExecutions, additionalInfo *vo.AdditionalInfo) (int, error) {
	count := 0
	synthesizersStrArray := make([]string, 0)
	for _, ruleOutput := range ruleExecutions.RuleOutputs {
		for _, evidence := range ruleOutput.Evidences {
			synthesizersStrArray = append(synthesizersStrArray, evidence.SynthesizerName)
		}
		synthesizersStrArray = utils.GetUniqueValuesFromString(synthesizersStrArray)
		for _, synthesizerStr := range synthesizersStrArray {
			srcSynthesizerPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.SynthesizersPath, synthesizerStr)
			if !utils.IsFolderExist(srcSynthesizerPath) {
				return count, fmt.Errorf("%s not found under %s", synthesizerStr, additionalInfo.PolicyCowConfig.PathConfiguration.SynthesizersPath)
			}
		}
	}
	count += len(synthesizersStrArray)
	return count, nil
}

func ExecuteSynthesizers(ruleExecutions *vo.CowRuleExecutions, additionalInfo *vo.AdditionalInfo, tempDir string) error {

	count, err := FetchSynthesizerCountForExecution(ruleExecutions, additionalInfo)
	if err != nil {
		return err
	}

	if count == 0 {
		return nil
	}

	bar := fetchProgressBar(int64(count))

	bar.Describe("Analysing synthesizers...")

	synthesizersPath := filepath.Join(tempDir, "synthesizers")

	err = os.MkdirAll(synthesizersPath, os.ModePerm)
	if err != nil {
		return err
	}

	s := spinner.New(spinner.CharSets[38], 100*time.Millisecond)
	s.Prefix = "synthesizer execution started..."
	s.Start()

	defer s.Stop()

	ruleNameMap := make(map[string]struct{}, 0)

	for _, ruleOutput := range ruleExecutions.RuleOutputs {
		if _, ok := ruleNameMap[ruleOutput.RuleName]; !ok {
			synthesizersStrArray := make([]string, 0)
			for _, evidence := range ruleOutput.Evidences {
				synthesizersStrArray = append(synthesizersStrArray, evidence.SynthesizerName)
			}
			if len(synthesizersStrArray) > 0 {
				synthesizersStrArray = utils.GetUniqueValuesFromString(synthesizersStrArray)

				for _, synthesizerStr := range synthesizersStrArray {
					bar.Describe(fmt.Sprintf("Executing %s synthesizer", synthesizerStr))
					tmpSynthesizerPath := filepath.Join(synthesizersPath, synthesizerStr)
					srcSynthesizerPath := utils.GetSynthesizerPathFromCatalog(additionalInfo, ruleExecutions.RuleName, synthesizerStr)
					if utils.IsFolderExist(srcSynthesizerPath) {
						err = cp.Copy(srcSynthesizerPath, tmpSynthesizerPath)
						if err != nil {
							return err
						}
						err = os.WriteFile(filepath.Join(tmpSynthesizerPath, "auto_generated_handler.py"), []byte(constants.SynthesizerAutoGeneratedCode), os.ModePerm)
						if err != nil {
							return err
						}
						synthesizer := &vo.SynthesizerV2{CnRuleName: ruleOutput.RuleName, CnRuleSetExecutionId: ruleExecutions.ExecutionID}

						synthesizerByts, err := json.Marshal(synthesizer)
						if err != nil {
							return err
						}
						err = os.WriteFile(filepath.Join(tmpSynthesizerPath, "synthesizer_input.json"), []byte(synthesizerByts), os.ModePerm)
						if err != nil {
							return err
						}

						cmd := exec.Command("python3", "-u", "auto_generated_handler.py")
						cmd.Dir = tmpSynthesizerPath

						_, err = cmd.Output()
						if err != nil {
							return err
						}

						outputByts, err := os.ReadFile(filepath.Join(tmpSynthesizerPath, "synthesizer_output.json"))
						if err == nil {
							evidences := make([]*vo.Evidence, len(ruleOutput.Evidences))
							err = json.Unmarshal(outputByts, &evidences)
							if err != nil {
								return err
							}

							evidenceMap := make(map[string]*vo.Evidence, 0)

							for _, evidence := range evidences {
								evidenceMap[evidence.FileName] = evidence
							}

							for _, evidence := range ruleOutput.Evidences {
								if val, ok := evidenceMap[evidence.Name]; ok {
									evidence.DataFilePath = val.DataFilePath
									evidence.MetaDataFilePath = val.MetaDataFilePath
									evidence.MetaFieldFilePath = val.MetaFieldFilePath
									evidence.CompliancePCT__ = val.CompliancePCT__
									evidence.ComplianceStatus__ = val.ComplianceStatus__
									evidence.ComplianceWeight__ = val.ComplianceWeight__
									if evidence.CompliancePCT__ <= 0 {
										evidence.CompliancePCT__ = val.CompliancePCT
									}
									if evidence.ComplianceWeight__ <= 0 {
										evidence.ComplianceWeight__ = val.ComplianceWeight
									}
									if stringUtils.IsEmpty(evidence.ComplianceStatus) {
										evidence.ComplianceStatus__ = val.ComplianceStatus
									}
								}
							}

						}

						s.Stop()

						bar.Add(1)
					}
				}
			}

		} else {
			ruleOutput.Evidences = nil
		}
		ruleNameMap[ruleOutput.RuleName] = struct{}{}

	}
	bar.Describe("finished")
	return nil

}

func fetchProgressBar(count int64) *progressbar.ProgressBar {
	bar := progressbar.NewOptions64(
		count,
		progressbar.OptionSetDescription("Executing"),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetWidth(10),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionShowBytes(false),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
	)
	bar.RenderBlank()
	return bar
}

func handleDependecyFlow(filePath, action string, ruleOutputs map[string]*vo.RuleOutputs,
	bar *progressbar.ProgressBar, ruleNameAndAliasInfo map[string]string, isVerbose, isExecuteFlow bool,
	additionalInfo *vo.AdditionalInfo, taskExecutions map[string]map[string]map[string]interface{}, tempDir string, isBinaryToBeCreated bool, ruleOutputsHelper *[]*vo.RuleOutputs) error {
	ruleDependency, err := getRuleDependencyVO(filePath)

	if err != nil {
		return err
	}

	err = utils.Validate.Struct(ruleDependency)
	errorDetails := utils.GetValidationError(err)
	if len(errorDetails) > 0 {
		errorByts, _ := json.Marshal(errorDetails)
		if len(errorByts) > 2 {
			return errors.New(string(errorByts))
		}
	}

	if fileInfo, err := os.Stat(filepath.Join(filePath, "files")); err == nil && fileInfo.IsDir() {
		err := cp.Copy(filepath.Join(filePath, "files"), filepath.Join(tempDir, "files"))
		if err != nil {
			return err
		}
	}
	if additionalInfo != nil && utils.IsNotEmpty(additionalInfo.RuleGroupName) && additionalInfo.FileInputs != nil {
		err = UpdateInputFiles(tempDir, additionalInfo.FileInputs)
		if err != nil {
			return err
		}

	}
	rulesNameArr := []string{}
	dependenciesArr := make([]topo.Dependency, 0)
	dependenciesArrV2 := make([]topo.Dependency, 0)

	nodes := []string{}

	ruleGroup := ``

	if utils.IsNotEmpty(ruleDependency.RuleGroup) {
		ruleGroup = "_" + ruleDependency.RuleGroup
	}

	ruleInfoMap := make(map[string]*vo.RuleInfo, 0)

	for _, ruleInfo := range ruleDependency.RulesInfo {
		ruleInfoMap[ruleInfo.RuleName] = ruleInfo
	}

	for _, ruleInfo := range ruleDependency.RulesInfo {

		if utils.IsStringContainsAny(ruleInfo.RuleName, ruleInfo.DependsOn) {
			return fmt.Errorf("cannot depends on the same rule %s", ruleInfo.RuleName)
		}

		ruleInfoMap[ruleInfo.RuleName] = ruleInfo
		nodes = append(nodes, ruleInfo.RuleName)
		rulesNameArr = append(rulesNameArr, ruleInfo.RuleName)
		tempRuleNameWithAlias := ruleInfo.RuleName + "-" + ruleInfo.AliasRef
		tempRuleNameWithGroupAndAlias := ruleInfo.RuleName + ruleGroup + "-" + ruleInfo.AliasRef
		ruleOutputs[ruleInfo.RuleName+ruleGroup] = &vo.RuleOutputs{RuleName: ruleInfo.RuleName, RuleGroup: ruleDependency.RuleGroup, AliasRef: ruleInfo.AliasRef}
		ruleOutputs[tempRuleNameWithGroupAndAlias] = &vo.RuleOutputs{RuleName: ruleInfo.RuleName, RuleGroup: ruleDependency.RuleGroup, AliasRef: ruleInfo.AliasRef}
		ruleNameAndAliasInfo[ruleInfo.AliasRef] = ruleInfo.RuleName
		ruleNameAndAliasInfo[ruleInfo.RuleName] = ruleInfo.AliasRef
		ruleNameAndAliasInfo[tempRuleNameWithAlias] = ruleInfo.AliasRef
		if len(ruleInfo.DependsOn) > 0 {
			for _, dependentRule := range ruleInfo.DependsOn {
				dependenciesArr = append(dependenciesArr, topo.Dependency{Child: ruleInfo.RuleName, Parent: dependentRule})
				if val, ok := ruleInfoMap[dependentRule]; ok {
					if utils.IsStringContainsAny(ruleInfo.RuleName, val.DependsOn) {
						return fmt.Errorf("cyclic dependency found for %s and %s", ruleInfo.RuleName, val.RuleName)
					}
					dependenciesArrV2 = append(dependenciesArrV2, topo.Dependency{Child: ruleInfo, Parent: val})
				}

			}
		}
	}

	sortRulesByDependency(dependenciesArr, rulesNameArr)

	ruleInfos := ruleDependency.RulesInfo

	sortRulesByDependencyV2(dependenciesArrV2, ruleInfos)

	for i, ruleInfo := range ruleInfos {
		rulePath := utils.GetRulePathFromCatalog(additionalInfo, ruleInfo.RuleName)
		if utils.IsNotValidRulePath(rulePath) {
			return fmt.Errorf("couldn't find the rule %v", ruleInfo.RuleName)
		}

		isLoaderToBeShown := i == 0

		tempDir := os.TempDir()
		if tempDir == "/tmp" {
			uuid := uuid.New().String()
			tempDir = filepath.Join(tempDir, uuid)
		}

		defer os.RemoveAll(tempDir)

		err = activityHelper(rulePath, ruleInfo.RuleName, action, ruleOutputs, ruleDependency, ruleNameAndAliasInfo, bar, isVerbose, isExecuteFlow,
			additionalInfo, taskExecutions, tempDir, isBinaryToBeCreated, isLoaderToBeShown, ruleInfo, ruleOutputsHelper)
		if err != nil {
			return err
		}

	}

	return nil
}

func sortRulesByDependency(dependenciesArr []topo.Dependency, rulesNameArr []string) {
	// Getter function to convert original elements to a generic type
	getter := func(i int) topo.Type {
		return rulesNameArr[i]
	}

	// Setter function to restore the original type of the data
	setter := func(i int, val topo.Type) {
		rulesNameArr[i] = val.(string)
	}

	// Perform topological sort
	if err := topo.Sort(rulesNameArr, dependenciesArr, getter, setter); err != nil {
		fmt.Printf("Error performing topological sort on slice of strings: %s\n", err)
	}
}

func sortRulesByDependencyV2(dependenciesArr []topo.Dependency, rulesInfoArr []*vo.RuleInfo) {

	// Getter function to convert original elements to a generic type
	getter := func(i int) topo.Type {
		return rulesInfoArr[i]
	}

	// Setter function to restore the original type of the data
	setter := func(i int, val topo.Type) {
		rulesInfoArr[i] = val.(*vo.RuleInfo)
	}

	// Perform topological sort
	if err := topo.Sort(rulesInfoArr, dependenciesArr, getter, setter); err != nil {
		fmt.Printf("Error inside new performing topological sort on slice of strings: %s\n", err)
	}
}

func getRuleName(rulePath string) string {
	if stringUtils.IsNotBlank(rulePath) {
		rulePath = strings.TrimSuffix(rulePath, "/")
	}

	if rulePathArr := strings.Split(rulePath, "/"); len(rulePathArr) > 1 {
		if ruleName := rulePathArr[len(rulePathArr)-1]; utils.IsNotEmpty(ruleName) {
			if strings.HasPrefix(ruleName, "Rule_") {
				ruleName = ruleName[len("Rule_"):]
			}
			return ruleName
		}
	}
	return rulePath
}

func isRulePath(rulePath string) bool {
	return utils.IsFileExist(filepath.Join(rulePath, constants.RuleFile)) || utils.IsFileExist(filepath.Join(rulePath, constants.RuleYamlFile))
}

func isRulesDependencyFolder(rulePath string) bool {
	return isRulesDependencyFolderV2(rulePath) || isRulesGroupFolder(rulePath)
}

func isRulesDependencyFolderV2(rulePath string) bool {
	return utils.IsFileExist(filepath.Join(rulePath, constants.RuleGroupFile))
}

func isRulesGroupFolder(rulePath string) bool {
	return utils.IsFileExist(filepath.Join(rulePath, constants.RuleGroupYAMLFileName))
}

func getRuleDependencyVO(rulePath string) (*vo.RuleDependency, error) {
	ruleDependency := &vo.RuleDependency{}
	if isRulesDependencyFolderV2(rulePath) {
		byts, err := os.ReadFile(filepath.Join(rulePath, constants.RuleGroupFile))
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(byts, ruleDependency)
		if err != nil {
			return nil, err
		}
	} else if isRulesGroupFolder(rulePath) {
		ruleDependencyCop, err := getRuleDependencyVOFromYAML(rulePath)

		if err != nil {
			return nil, err
		}

		ruleDependency = ruleDependencyCop

	}
	return ruleDependency, nil
}

func getRuleDependencyVOFromYAML(rulePath string) (*vo.RuleDependency, error) {

	ruleGroupYAMLVO := &vo.RuleGroupYAMLVO{}
	ruleDependency := &vo.RuleDependency{}
	byts, err := os.ReadFile(filepath.Join(rulePath, constants.RuleGroupYAMLFileName))
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(byts, ruleGroupYAMLVO)
	if err != nil {
		return nil, err
	}

	inputsYAMLFilePath := filepath.Join(rulePath, constants.TaskInputYAMLFile)
	if utils.IsFileExist(inputsYAMLFilePath) {
		ruleGroupInputs := &vo.UserInputsVO{}
		byts, err := os.ReadFile(inputsYAMLFilePath)
		if err != nil {
			return nil, err
		}
		err = yaml.Unmarshal(byts, ruleGroupInputs)
		if err != nil {
			return nil, err
		}

		ruleDependency.Inputs = ruleGroupInputs
	}

	ruleDependency.RuleGroup = ruleGroupYAMLVO.Meta.Name
	ruleDependency.RulesInfo = ruleGroupYAMLVO.Spec.RulesInfo
	ruleDependency.Synthesizer = ruleGroupYAMLVO.Spec.Synthesizer

	targetOutputVariables := make([]string, 0)
	srcInputVariables := make([]string, 0)

	selfAssignVars := make([]string, 0)
	incorrectFormatErrors := make([]string, 0)
	sourceRefFormatErrors := make([]string, 0)
	targetRefFormatErrors := make([]string, 0)
	inValidFieldTypes := make([]string, 0)

	for _, iomap := range ruleGroupYAMLVO.Spec.IoMap {
		iomapArr := strings.Split(iomap, ":=")

		if len(iomapArr) < 2 {
			incorrectFormatErrors = append(incorrectFormatErrors, fmt.Sprintf("'%s'", iomap))
			continue
		}
		targetArr := strings.Split(iomapArr[0], ".")
		if len(targetArr) < 3 {
			targetRefFormatErrors = append(targetRefFormatErrors, fmt.Sprintf("'%s'", iomap))
			continue
		}
		sourceArr := strings.Split(iomapArr[1], ".")
		if len(sourceArr) < 3 {
			sourceRefFormatErrors = append(sourceRefFormatErrors, fmt.Sprintf("'%s'", iomap))
			continue
		}

		if sourceArr[0] == targetArr[0] && sourceArr[1] == targetArr[1] && sourceArr[2] == targetArr[2] {
			selfAssignVars = append(selfAssignVars, fmt.Sprintf("'%s'", targetArr[2]))
			continue
		}

		if targetArr[1] == "Input" && targetArr[0] == "*" {
			targetOutputVariables = append(targetOutputVariables, fmt.Sprintf("'%s'", targetArr[2]))
			continue
		}

		if sourceArr[1] == "Output" && sourceArr[0] == "*" {
			srcInputVariables = append(srcInputVariables, fmt.Sprintf("'%s'", sourceArr[2]))
			continue
		}

		fieldTypes := []string{"Input", "Output"}

		if !utils.SliceContains(fieldTypes, sourceArr[1]) || !utils.SliceContains(fieldTypes, targetArr[1]) {
			inValidFieldTypes = append(inValidFieldTypes, iomap)
		}

		ruleDependency.RefMap = append(ruleDependency.RefMap, &vo.RefStruct{
			SourceRef: vo.FieldMap{
				AliasRef:  sourceArr[0],
				FieldType: sourceArr[1],
				VarName:   sourceArr[2],
			},
			TargetRef: vo.FieldMap{
				AliasRef:  targetArr[0],
				FieldType: targetArr[1],
				VarName:   targetArr[2],
			},
		})

	}

	errorMsgs := make([]string, 0)

	if len(targetOutputVariables) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Assigning the output variable {%s} as input to the flow is not allowed.", strings.Join(targetOutputVariables, ",")))
	}

	if len(srcInputVariables) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("You cannot use the output variable of the rule as an input. {%s}", strings.Join(srcInputVariables, ",")))
	}

	if len(selfAssignVars) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Cannot assign a variable to itself. {%s}", strings.Join(selfAssignVars, ",")))
	}

	if len(incorrectFormatErrors) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("The provided mappings are incorrect. {%s}", strings.Join(incorrectFormatErrors, ",")))
	}

	if len(sourceRefFormatErrors) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Invalid source format. {%s}", strings.Join(sourceRefFormatErrors, ",")))
	}

	if len(targetRefFormatErrors) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Invalid target format. {%s}", strings.Join(targetRefFormatErrors, ",")))
	}

	if len(inValidFieldTypes) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Invalid field types. {%s}", strings.Join(inValidFieldTypes, ",")))
	}

	if len(errorMsgs) > 0 {

		if len(errorMsgs) == 1 {
			return nil, errors.New(errorMsgs[0])
		}

		orderedErrorMsgs := make([]string, 0)

		for i, errorMsg := range errorMsgs {
			orderedErrorMsgs = append(orderedErrorMsgs, fmt.Sprintf("%d. %s", i+1, errorMsg))
		}

		return nil, errors.New(strings.Join(orderedErrorMsgs, "\n"))
	}

	return ruleDependency, nil
}

func isValidRulePath(rulePath string) bool {
	return isRulePath(rulePath)
}

func executeRuleHelper(rulePath, ruleName string, ruleOutputs map[string]*vo.RuleOutputs,
	ruleDependency *vo.RuleDependency, ruleNameAndAliasInfo map[string]string,
	bar *progressbar.ProgressBar, isVerbose bool, additionalInfo *vo.AdditionalInfo,
	taskExecutions map[string]map[string]map[string]interface{}, tempDir string, isLoaderToBeShown bool, ruleOutputsHelper *[]*vo.RuleOutputs) error {

	return activityHelper(rulePath, ruleName, "Executing", ruleOutputs, ruleDependency, ruleNameAndAliasInfo, bar, isVerbose, true, additionalInfo, taskExecutions, tempDir, false, isLoaderToBeShown, nil, ruleOutputsHelper)

}

func ExecuteTask(executeTaskVO *vo.TaskExecutionVO, taskPath string, additionalInfo *vo.AdditionalInfo) (*vo.TaskOutputResponse, error) {
	if !utils.IsMinioCredAvailable() {
		return nil, errors.New("the 'minio' credentials are not provided. Kindly include them in the environment file and restart the server")
	}
	additionalInfo.ExecutionID = uuid.New().String()

	executionPath := additionalInfo.PolicyCowConfig.PathConfiguration.ExecutionPath
	var executionDir string
	if utils.IsFolderExist(executionPath) {
		executionDir = filepath.Join(executionPath, "tasks", executeTaskVO.TaskName+"-"+additionalInfo.ExecutionID)
	} else {
		executionDir = filepath.Join(os.TempDir(), additionalInfo.ExecutionID, executeTaskVO.TaskName)
	}
	if err := os.MkdirAll(executionDir, os.ModePerm); err != nil {
		return nil, fmt.Errorf("failed to create execution directory: %w", err)
	}

	opt := cp.Options{
		Skip: func(srcInfo fs.FileInfo, src string, dest string) (bool, error) {
			pathArr := strings.Split(src, string(os.PathSeparator))
			isFilesFolder := false

			if len(pathArr) > 0 {
				isFilesFolder = pathArr[len(pathArr)-1] == "files"
			}
			return strings.HasSuffix(src, "task_output.json") || strings.HasSuffix(src, "task_input.json") || strings.HasSuffix(src, "logs.txt") || isFilesFolder, nil
		},
	}

	err := cp.Copy(taskPath, executionDir, opt)
	if err != nil {
		return nil, fmt.Errorf("error happens while copying task folder: %s", err.Error())
	}

	if utils.IsPythonFlow(executionDir) {
		appConnPath := additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationTypesPath
		err = cp.Copy(filepath.Join(appConnPath, "python", filepath.Base(appConnPath)), filepath.Join(executionDir, filepath.Base(appConnPath)))
		if err != nil {
			return nil, fmt.Errorf("error happens while copying applicationtypes folder: %s", err.Error())
		}
		cp.Copy(filepath.Join(appConnPath, "python", "requirements.txt"), filepath.Join(executionDir, filepath.Base(appConnPath), "requirements.txt"))

		InstallPythonDependenciesWithRequirementsTxtFile(executionDir)
		InstallPythonDependenciesWithRequirementsTxtFile(filepath.Join(executionDir, "applicationtypes"))
	}

	yamlPath := filepath.Join(executionDir, constants.TaskInputYAMLFile)
	yamlBytes, err := os.ReadFile(yamlPath)
	if err != nil {
		return &vo.TaskOutputResponse{TaskOutputs: &vo.TaskOutputsVO{Error: fmt.Sprintf("Missing inputs.yaml file in task folder: %s", err)}}, nil
	}
	var taskInput vo.TaskInputV2
	err = yaml.Unmarshal(yamlBytes, &taskInput)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling inputs.yaml: %s", err)
	}
	for key := range taskInput.UserInputs {
		if val, exists := executeTaskVO.TaskInputs.Inputs[key]; exists {
			taskInput.UserInputs[key] = val
		} else {
			taskInput.UserInputs[key] = ""
		}
	}
	if taskInput.UserObject.App != nil && executeTaskVO.Application != nil {
		if utils.IsNotEmpty(executeTaskVO.Application.CredentialType) && len(executeTaskVO.Application.CredentialValues) > 0 {
			taskInput.UserObject.App.UserDefinedCredentials = map[string]interface{}{
				executeTaskVO.Application.CredentialType: executeTaskVO.Application.CredentialValues,
			}
		}
		if utils.IsNotEmpty(executeTaskVO.Application.ApplicationURL) {
			taskInput.UserObject.App.ApplicationURL = executeTaskVO.Application.ApplicationURL
		}
	}

	updatedYamlBytes, err := yaml.Marshal(taskInput)
	if err != nil {
		return &vo.TaskOutputResponse{TaskOutputs: &vo.TaskOutputsVO{Error: fmt.Sprintf("Failed to update inputs.yaml: %s", err)}}, nil
	}

	if err := os.WriteFile(yamlPath, updatedYamlBytes, os.ModePerm); err != nil {
		return &vo.TaskOutputResponse{TaskOutputs: &vo.TaskOutputsVO{Error: fmt.Sprintf("Failed to write updated inputs.yaml: %s", err.Error())}}, nil
	}

	var commandSeq string

	if utils.IsPythonFlow(executionDir) {
		commandSeq = "python3 -u autogenerated_main.py"
	} else {
		replaceLibraryPathsInGoMod(executionDir, additionalInfo)
		commandSeq = "go mod tidy && go run *.go"
	}

	cmd := exec.Command("bash", "-c", commandSeq)
	cmd.Dir = executionDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return &vo.TaskOutputResponse{TaskOutputs: &vo.TaskOutputsVO{Error: fmt.Sprintf("Task execution failed: %s\nOutput: %s", err.Error(), string(output))}}, nil
	}
	outputData := make(map[string]interface{})

	outputByts, err := os.ReadFile(path.Join(executionDir, "task_output.json"))
	if err != nil {
		return &vo.TaskOutputResponse{TaskOutputs: &vo.TaskOutputsVO{Error: fmt.Sprintf("Task execution failed: task_output.json file is missing: %s", err)}}, nil
	}

	if err := json.Unmarshal(outputByts, &outputData); err != nil {
		return &vo.TaskOutputResponse{TaskOutputs: &vo.TaskOutputsVO{Error: fmt.Sprintf("Failed to parse task_output.json: %s", err)}}, nil
	}

	var executions *executions.RuleExecutions

	ruleExecutions := &vo.CowRuleExecutions{
		ExecutionID: additionalInfo.ExecutionID,
		RunDetails: map[string]map[string]map[string]interface{}{
			executeTaskVO.TaskName: {"TaskOutputs": outputData},
		},
		Type: constants.YAMLKindTypeTask,
	}

	err = executions.Create(ruleExecutions, additionalInfo, "")
	if err != nil {
		return nil, err
	}

	ReplaceExecutionData(ruleExecutions, additionalInfo)

	logPath := filepath.Join(executionDir, "logs.txt")
	if logBytes, errLog := os.ReadFile(logPath); errLog == nil {
		return &vo.TaskOutputResponse{
			TaskOutputs: &vo.TaskOutputsVO{
				Error: fmt.Sprintf("Task execution failed with error. Logs: %s", string(logBytes)),
			},
		}, nil
	}

	defer os.RemoveAll(executionDir)

	if errVal, exists := outputData["error"]; exists {
		return &vo.TaskOutputResponse{TaskOutputs: &vo.TaskOutputsVO{Error: fmt.Sprint(errVal)}}, nil
	}

	outputs, ok := outputData["Outputs"].(map[string]interface{})
	if !ok {
		return &vo.TaskOutputResponse{TaskOutputs: &vo.TaskOutputsVO{Error: fmt.Sprintf("'Outputs' has an invalid format. Expected map[string]interface{}, but got %T", outputs)}}, nil
	}

	return &vo.TaskOutputResponse{TaskOutputs: &vo.TaskOutputsVO{Outputs: outputs}}, nil

}

func activityHelper(rulePath, ruleName, action string, ruleOutputs map[string]*vo.RuleOutputs,
	ruleDependency *vo.RuleDependency, ruleNameAndAliasInfo map[string]string,
	bar *progressbar.ProgressBar, isVerbose, isExecuteCall bool, additionalInfo *vo.AdditionalInfo,
	taskExecutions map[string]map[string]map[string]interface{}, tempDir string, isBinaryToBeCreated bool, isLoaderToBeShown bool, ruleInfo *vo.RuleInfo, ruleOutputsHelper *[]*vo.RuleOutputs) error {

	s := spinner.New(spinner.CharSets[38], 100*time.Millisecond) // Build our new spinner
	if isLoaderToBeShown {
		s.Prefix = fmt.Sprintf("%s %s...", action, ruleName)
		s.Start()

		defer func(spinr *spinner.Spinner) {
			if spinr.Active() {
				spinr.Stop()
			}
		}(s)
	}
	srcRuleDir := rulePath
	if utils.IsNotValidRulePath(rulePath) {
		srcRuleDir = utils.GetRuleNameFromAdditionalInfoWithRuleName(ruleName, additionalInfo)
	}
	tmpRuleDir := filepath.Join(tempDir, ruleName)
	if ruleInfo != nil && utils.IsNotEmpty(ruleInfo.AliasRef) {
		tmpRuleDir = filepath.Join(tmpRuleDir, ruleInfo.AliasRef)
	}
	if !additionalInfo.UpdateUserInputs {
		err := cp.Copy(srcRuleDir, tmpRuleDir)
		if err != nil {
			return err
		}
	}
	ruleYamlPath := filepath.Join(tmpRuleDir, constants.RuleYamlFile)

	var taskInput vo.TaskInput

	if utils.IsFileExist(ruleYamlPath) {

		ruleYAML, err := GetRuleYAML(ruleYamlPath)
		if err != nil {
			return fmt.Errorf("not a valid rule.yaml. error:%s", err.Error())
		}

		if ruleYAML != nil && ruleYAML.Meta != nil && utils.IsNoneEmpty(ruleYAML.Meta.Tags) {
			additionalInfo.RuleMetaTags = ruleYAML.Meta.Tags
		}

		ruleSet, err := GetRuleSetFromYAML(ruleYamlPath)
		if err != nil {
			return err
		}

		inputYAMLFileByts, err := os.ReadFile(filepath.Join(tmpRuleDir, constants.TaskInputYAMLFile))
		if err == nil {
			err = yaml.Unmarshal(inputYAMLFileByts, &taskInput)
			if err != nil {
				return fmt.Errorf("not a valid rule input structure. error :%s", err.Error())
			}

			for inpKey, inpValue := range taskInput.UserInputs {
				if userInputsMap, ok := inpValue.(map[interface{}]interface{}); ok {
					taskInput.UserInputs[inpKey] = utils.ConvertMap(userInputsMap)
				}
			}
			for key := range ruleSet.Rules[0].RuleIOValues.Inputs {
				if userInputValue, ok := taskInput.UserInputs[key]; ok {
					if strValue, ok := userInputValue.(string); ok {
						userInputValue = strings.TrimSpace(strValue)
						if isExecuteCall && userInputValue == constants.MinioFilePath {
							userInputValue = ""
						}
					}
					ruleSet.Rules[0].RuleIOValues.Inputs[key] = userInputValue
					for _, input := range ruleSet.Rules[0].RuleIOValues.InputsMeta__ {
						if input.Name == key {
							input.DefaultValue = userInputValue
						}
					}
				}

			}
			taskInput.UserInputs = ruleSet.Rules[0].RuleIOValues.Inputs

			if additionalInfo.RuleExecutionVO != nil {
				if len(additionalInfo.RuleExecutionVO.RuleInputs) > 0 {
					inputsMap, errorResp := RuleInputsToMap(ruleName, additionalInfo.RuleExecutionVO.RuleInputs)
					if errorResp == nil && len(inputsMap) > 0 {

						userInputs := taskInput.UserInputs
						if taskInput.UserInputs == nil {
							userInputs = make(map[string]interface{}, 0)
						}
						maps.Copy(userInputs, inputsMap)

						taskInput.UserInputs = userInputs

						for _, input := range ruleSet.Rules[0].RuleIOValues.InputsMeta__ {
							if value, exists := taskInput.UserInputs[input.Name]; exists {
								input.DefaultValue = value
							}
						}
					}
				}
				if taskInput.UserObject.App != nil {
					if utils.IsNotEmpty(additionalInfo.RuleExecutionVO.CredentialType) && len(additionalInfo.RuleExecutionVO.CredentialValues) > 0 {
						taskInput.UserObject.App.UserDefinedCredentials = map[string]interface{}{
							additionalInfo.RuleExecutionVO.CredentialType: additionalInfo.RuleExecutionVO.CredentialValues,
						}
					}
					if utils.IsNotEmpty(additionalInfo.RuleExecutionVO.ApplicationURL) {
						taskInput.UserObject.App.ApplicationURL = additionalInfo.RuleExecutionVO.ApplicationURL
					}

					if len(additionalInfo.RuleExecutionVO.LinkedApplications) > 0 {
						updateLinkedApplicationCredentials(taskInput.UserObject.App.LinkedApplications, additionalInfo.RuleExecutionVO.LinkedApplications)
					}
				}

				for _, app := range taskInput.UserObject.Apps {
					if app != nil {
						for _, ruleApps := range additionalInfo.RuleExecutionVO.Applications {
							if reflect.DeepEqual(app.AppTags, ruleApps.AppTags) {
								if utils.IsNotEmpty(ruleApps.ApplicationID) {
									fetchedCredentials, err := FetchAppCredentials(ruleApps.ApplicationID, additionalInfo)
									if err != nil {
										return fmt.Errorf("error fetching credentials for app %s: %v", ruleApps.ApplicationID, err)
									}
									if credentialType, ok := fetchedCredentials["credentialType"].(string); ok {
										if appCredential, ok := app.UserDefinedCredentials.(map[interface{}]interface{}); ok {
											appCred := utils.ConvertMap(appCredential)
											if _, exists := appCred[credentialType]; exists {
												if userDefinedData, ok := fetchedCredentials["userDefinedData"].([]interface{}); ok {
													credentialValues := make(map[string]interface{})
													for _, data := range userDefinedData {
														if dataMap, ok := data.(map[string]interface{}); ok {
															if name, ok := dataMap["name"].(string); ok {
																if value, ok := dataMap["value"].(string); ok {
																	credentialValues[name] = value
																}
															}
														}
													}
													app.UserDefinedCredentials = map[string]interface{}{
														credentialType: credentialValues,
													}
												}
											} else {
												return fmt.Errorf("credentialType %s not matched with fetching credentials from ApplicationID - %s", credentialType, ruleApps.ApplicationID)
											}
										}
										if appURL, ok := fetchedCredentials["appURL"].(string); ok {
											app.ApplicationURL = appURL
										}
									}
								} else {
									if utils.IsNotEmpty(ruleApps.CredentialType) && len(ruleApps.CredentialValues) > 0 {
										app.UserDefinedCredentials = map[string]interface{}{
											ruleApps.CredentialType: ruleApps.CredentialValues,
										}
									}
									if utils.IsNotEmpty(ruleApps.ApplicationURL) {
										app.ApplicationURL = ruleApps.ApplicationURL
									}
									if len(ruleApps.LinkedApplications) > 0 {
										updateLinkedApplicationCredentials(app.LinkedApplications, ruleApps.LinkedApplications)
									}
								}
							}
						}
					}
				}

				if utils.IsNotEmpty(additionalInfo.RuleExecutionVO.FromDate) && utils.IsNotEmpty(additionalInfo.RuleExecutionVO.ToDate) {
					taskInput.FromDate_, _ = time.Parse("2006-01-02", additionalInfo.RuleExecutionVO.FromDate)
					taskInput.ToDate_, _ = time.Parse("2006-01-02", additionalInfo.RuleExecutionVO.ToDate)
				}
			}

			taskInputBytes, err := yaml.Marshal(taskInput)
			if err != nil {
				return err
			}

			if err := os.WriteFile(filepath.Join(tmpRuleDir, constants.TaskInputYAMLFile), taskInputBytes, 0644); err != nil {
				return err
			}
		}

		if !isExecuteCall {
			var taskInput vo.TaskInput

			inputYAMLFileByts, err := os.ReadFile(filepath.Join(tmpRuleDir, constants.TaskInputYAMLFile))
			if err == nil {
				err = yaml.Unmarshal(inputYAMLFileByts, &taskInput)
				if err != nil {
					return fmt.Errorf("not a valid rule input structure. error :%s", err.Error())
				}

				for _, app := range taskInput.SystemInputs.UserObject.Apps {
					var appData *vo.UserDefinedApplicationVO
					applicationYamlContent, err := os.ReadFile(filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationTypeConfigPath, fmt.Sprintf("%s.yaml", (app.ApplicationName))))
					if err := yaml.Unmarshal(applicationYamlContent, &appData); err != nil {
						return err
					}
					if err == nil {
						for i, taskInfo := range ruleSet.Rules[0].TasksInfo {
							task, ok := taskInfo.(*vo.TaskInfo)
							if !ok {
								return fmt.Errorf("invalid task format in TasksInfo at index %d", i)
							}
							if task.AppTags["appType"][0] == appData.Meta.Labels["appType"][0] {
								appTags := task.AppTags
								for labelKey, labelValues := range appData.Meta.Labels {
									if _, exists := appTags[labelKey]; !exists {
										appTags[labelKey] = []string{}
									}
									for _, label := range labelValues {
										found := false
										for _, tag := range appTags[labelKey] {
											if tag == label {
												found = true
												break
											}
										}
										if !found {
											appTags[labelKey] = labelValues
										}
									}
								}
							}
							ruleSet.Rules[0].TasksInfo[i] = task
						}
					}
				}
			}
		}

		ruleJson, _ := json.Marshal(ruleSet)
		ruleJSONPath := filepath.Join(tmpRuleDir, constants.RuleFile)
		err = os.WriteFile(ruleJSONPath, ruleJson, 0644)
		if err != nil {
			return err
		}

		if len(additionalInfo.RuleInputs) > 0 {

			for _, rule := range ruleSet.Rules {
				if rule.RuleName == ruleName {
					rule.RuleIOValues.Inputs = additionalInfo.RuleInputs

				}
			}

			fileByts, err := json.MarshalIndent(ruleSet, "", "	")

			if err == nil {
				os.WriteFile(ruleJSONPath, fileByts, os.ModePerm)
			}
		}
	}

	if utils.IsNotEmpty(additionalInfo.RuleName) && additionalInfo.FileInputs != nil {
		err := UpdateInputFiles(tmpRuleDir, additionalInfo.FileInputs)
		if err != nil {
			return err
		}
	}
	if ruleInfo != nil {
		if len(ruleInfo.UserInputs) > 0 {
			filesFolder := filepath.Join(tmpRuleDir, "files")
			if utils.IsFolderNotExist(filesFolder) {
				os.MkdirAll(filesFolder, os.ModePerm)
			}
			inputByts, err := json.MarshalIndent(ruleInfo.UserInputs, " ", "")
			if err == nil {
				os.WriteFile(filepath.Join(filesFolder, "TaskInputValue.json"), inputByts, os.ModePerm)
			}
		}
	}
	if len(additionalInfo.RuleInputVOs) > 0 && utils.IsNotEmpty(additionalInfo.RuleGroupName) {
		for _, rule := range additionalInfo.RuleInputVOs {
			if rule.RuleName == filepath.Base(tmpRuleDir) || rule.RuleName == filepath.Base(filepath.Dir(tmpRuleDir)) {
				err := UpdateInputFiles(tmpRuleDir, rule.FileInputs)
				if err != nil {
					return err
				}
			}
		}

	}

	additionalInfo.RuleExecutionID = utils.GetNewUUID()
	bar.Describe(action + " " + ruleName)

	outputFile := filepath.Join(tmpRuleDir, "output.json")
	if utils.IsFileExist(outputFile) {
		if err := os.Truncate(outputFile, 0); err != nil {
			return err
		}
	}

	logFile := filepath.Join(tmpRuleDir, constants.RuleExecutionLogFile)
	if utils.IsFileExist(logFile) {
		if err := os.Truncate(logFile, 0); err != nil {
			return err
		}
	}

	ruleGroup := ``

	if ruleDependency != nil && utils.IsNotEmpty(ruleDependency.RuleGroup) {
		ruleGroup = "_" + ruleDependency.RuleGroup
	}

	ruleNameWithGroup := ruleName + ruleGroup

	tempRuleNameWithAlias := ruleName
	tempRuleNameWithGroupAndAlias := ruleNameWithGroup

	if ruleInfo != nil {
		if utils.IsNotEmpty(ruleInfo.AliasRef) {
			tempRuleNameWithAlias += "-" + ruleInfo.AliasRef
			tempRuleNameWithGroupAndAlias += "-" + ruleInfo.AliasRef
		}
	}

	handleRuleInputs(tmpRuleDir, tempRuleNameWithAlias, tempRuleNameWithGroupAndAlias, ruleOutputs, ruleDependency, ruleNameAndAliasInfo, additionalInfo, isBinaryToBeCreated, ruleInfo, ruleName, isExecuteCall)

	if len(additionalInfo.ValidationErrors) > 0 {
		return errors.New(strings.Join(additionalInfo.ValidationErrors, ", "))
	}

	if isExecuteCall {

		defer func(addInfo *vo.AdditionalInfo) {

			if additionalInfo.PreserveRuleExecutionSetUp {
				filter := func(info os.FileInfo, src, dest string) (bool, error) {
					if strings.HasPrefix(info.Name(), ".") {
						return true, nil
					}
					return false, nil
				}

				// rulePath := filepath.Join(tempDir)
				if execFolderPath := additionalInfo.PolicyCowConfig.PathConfiguration.ExecutionPath; utils.IsFolderExist(execFolderPath) && utils.IsFolderExist(rulePath) {
					cp.Copy(filepath.Join(tempDir, ruleName), filepath.Join(execFolderPath, "rules", ruleName+"-"+additionalInfo.ExecutionID), copy.Options{Skip: filter})
				}
			}

		}(additionalInfo)

		pushProgressToChannel := func(ruleProgress chan *vo.RuleProgressVO) error {

			fileByts, err := os.ReadFile(filepath.Join(tmpRuleDir, constants.FileNameProgress))
			if err != nil {
				return err
			}
			ruleProgressVO := &vo.RuleProgressVO{}
			json.Unmarshal(fileByts, ruleProgressVO)
			if utils.IsNotEmpty(ruleProgressVO.Status) {
				if len(additionalInfo.RuleOutputs) > 0 && ruleProgressVO.Status != "ERROR" {
					maps.Copy(ruleProgressVO.Outputs, additionalInfo.RuleOutputs)
					ruleProgressVO.Status = "COMPLETED"
				} else if ruleProgressVO.Status == "COMPLETED" && len(ruleProgressVO.Outputs) == 0 {
					ruleProgressVO.Status = "COMPLETED"
				} else if ruleProgressVO.Status != "ERROR" {
					ruleProgressVO.Status = "INPROGRESS"
				}

				ruleProgress <- ruleProgressVO
			}
			return nil
		}

		if additionalInfo.RuleProgressWorker != nil {

			utils.GoRoutine(context.Background(), func() {
				fileReadFailedCount := 0
				for {
					time.Sleep(1 * time.Second)
					err := pushProgressToChannel(additionalInfo.RuleProgressWorker.RuleProgressChannel)
					if err != nil {
						fileReadFailedCount++
						if fileReadFailedCount > 5 {
							break
						}

					}
					if additionalInfo.RuleProgressWorker.Quit {
						break
					}
				}
			})
		}

		commandSeq := ``

		goModFilePath := filepath.Join(tmpRuleDir, "go.mod")
		if _, err := os.Stat(goModFilePath); os.IsNotExist(err) {
			commandSeq += fmt.Sprintf("go mod init %s &&", ruleName)
		} else {
			replaceLibraryPathsInGoMod(goModFilePath, additionalInfo)
		}

		if _, err := os.Stat(tmpRuleDir + string(os.PathSeparator) + "go.sum"); os.IsNotExist(err) {
			commandSeq += "go mod tidy &&  "

		}

		commandSeq += `go run *.go`

		cmd := exec.Command("bash", "-c", commandSeq)
		cmd.Dir = tmpRuleDir

		output, err := cmd.Output()

		defer func() {
			if additionalInfo.RuleProgressWorker != nil {
				pushProgressToChannel(additionalInfo.RuleProgressWorker.RuleProgressChannel)
				additionalInfo.RuleProgressWorker.Quit = true
			}
		}()

		logsByts, _ := os.ReadFile(filepath.Join(tmpRuleDir, constants.LogsFileName))

		isError := false

		if isVerbose {
			if s != nil && s.Active() {
				s.Stop()
			}
			fmt.Println()
			if len(output) > 0 {
				color.Green("%s output :\n %s", ruleName, string(output))
			}

			defer func(isError *bool, logsbyts []byte) {
				fmt.Println()
				if *isError {
					color.Red("%s logs :\n %s", ruleName, string(logsByts))
				} else {
					color.Yellow("%s logs :\n %s", ruleName, string(logsByts))
				}
				fmt.Println()

			}(&isError, logsByts)

			fmt.Println()
		}

		if err != nil {
			isError = true
			additionalInfo.PreserveRuleExecutionSetUp = true
			return err
		}

		if utils.IsFileExist(outputFile) {
			fileByts, err := os.ReadFile(outputFile)

			if err != nil {
				isError = true
				return err
			}

			outputs := make(map[string]interface{}, 0)

			err = json.Unmarshal(fileByts, &outputs)
			if err != nil {
				//return err TODO : Need to handle the O/P Unavailability
			}

			taskFolders, err := os.ReadDir(tmpRuleDir)
			if err != nil {
				return fmt.Errorf("error reading ruledir. error: %v", err.Error())
			}

			var ruleLog vo.RuleLogData
			ruleLog.RuleName = ruleName
			if taskInput.UserObject.App != nil {
				ruleLog.ApplicationName = taskInput.UserObject.App.ApplicationName
			} else {
				ruleLog.ApplicationName = taskInput.UserObject.Apps[0].ApplicationName
			}
			logDataFileExist := false

			for _, taskFolder := range taskFolders {
				if taskFolder.IsDir() {
					logFilePath := filepath.Join(tmpRuleDir, taskFolder.Name(), constants.TaskExecutionLogDataFile)
					if utils.IsFileExist(logFilePath) {
						logFile, err := os.Open(logFilePath)
						if err != nil {
							return fmt.Errorf("error opening TaskLogs.ndjson: %v", err)
						}
						defer logFile.Close()

						var taskLog vo.TaskLog
						taskLog.TaskName = taskFolder.Name()

						scanner := bufio.NewScanner(logFile)
						for scanner.Scan() {
							var logEntry vo.LogEntry
							if err := json.Unmarshal(scanner.Bytes(), &logEntry); err != nil {
								return fmt.Errorf("error parsing in TaskLogs.ndjson: %v", err)
							}
							taskLog.Logs = append(taskLog.Logs, logEntry)
						}

						if err := scanner.Err(); err != nil {
							return fmt.Errorf("error reading TaskLogs.ndjson: %v", err)
						}
						ruleLog.Tasks = append(ruleLog.Tasks, taskLog)
						logDataFileExist = true
					}
				}
			}
			if logDataFileExist {
				ruleLogDataBytes, err := json.MarshalIndent(ruleLog, "", "  ")
				if err != nil {
					return fmt.Errorf("error marshalling ruleLog data: %v", err)
				}

				logFilePath := filepath.Join(tmpRuleDir, constants.RuleExecutionLogDataFile)
				if err := os.WriteFile(logFilePath, ruleLogDataBytes, os.ModePerm); err != nil {
					return fmt.Errorf("error writing RuleLogs.json:%v", err)
				}

				if utils.IsFileExist(logFilePath) {
					minioEndpoint := utils.Getenv(constants.EnvMinioLoginURL, "cowstorage:9000")

					log.SetOutput(io.Discard)

					minioClient, err := cowStorage.RegisterMinio(minioEndpoint, utils.Getenv(constants.EnvMinioRootUser, ""), utils.Getenv(constants.EnvMinioRootPassword, ""), constants.BucketNameLog)

					if err == nil && minioClient != nil {
						folderPath := ruleName + "/" + additionalInfo.ExecutionID + "/" + constants.RuleExecutionLogDataFile

						minioFileVO, err := cowStorage.UploadFileToMinioV2(minioClient, constants.BucketNameLog, folderPath, logFilePath, "application/text")
						if err == nil {
							outputs[constants.RuleExecutionLogDataKey] = minioFileVO.ObjectPath
						}

					}
					outputsBytes, err := json.MarshalIndent(outputs, "", "  ")
					if err != nil {
						return fmt.Errorf("error marshalling outputs: %v", err)
					}
					if err := os.WriteFile(outputFile, outputsBytes, os.ModePerm); err != nil {
						return fmt.Errorf("error writing in outputs.json: %v", err)
					}
				}
			}

			calculateComplianceInfo(outputs, additionalInfo) // TODO: Ignore the error as of now

			func() {

				if utils.IsFileExist(logFile) {
					minoEndpoint := utils.Getenv(constants.EnvMinioLoginURL, "cowstorage:9000")

					// Supress log
					log.SetOutput(io.Discard)
					minioClient, err := cowStorage.RegisterMinio(minoEndpoint, utils.Getenv(constants.EnvMinioRootUser, ""), utils.Getenv(constants.EnvMinioRootPassword, ""), constants.BucketNameLog)

					if err == nil && minioClient != nil {
						folderPath := ruleName + "/" + additionalInfo.ExecutionID + "/" + constants.RuleExecutionLogFile
						bucketName, prefix := cowStorage.GetBucketAndPrefix(constants.BucketNameLog)
						folderPath = prefix + folderPath
						_, _ = minioClient.FPutObject(context.Background(), bucketName, folderPath, logFile, minio.PutObjectOptions{})

					}

				}
			}()

			if errorMsg, ok := outputs["error"]; ok || additionalInfo.PreserveRuleExecutionSetUp {
				if ok {
					additionalInfo.ErrorOccured = true
					additionalInfo.PreserveRuleExecutionSetUp = true
				}

				// filter := func(info os.FileInfo, src, dest string) (bool, error) {
				// 	if strings.HasPrefix(info.Name(), ".") {
				// 		return true, nil
				// 	}
				// 	return false, nil
				// }

				// // rulePath := filepath.Join(tempDir)
				// if execFolderPath := additionalInfo.PolicyCowConfig.PathConfiguration.ExecutionPath; utils.IsFolderExist(execFolderPath) && utils.IsFolderExist(rulePath) {
				// 	cp.Copy(filepath.Join(tempDir, ruleName), filepath.Join(execFolderPath, "rules", ruleName+"-"+additionalInfo.ExecutionID), copy.Options{Skip: filter})
				// }

				if additionalInfo.ErrorOccured {
					isError = true

					// if isVerbose {
					// 	isError = true
					// 	logsByts, err := os.ReadFile(filepath.Join(tmpRuleDir, constants.LogsFileName))
					// 	if err == nil {
					// 		color.Red("%s output :\n %s", ruleName, string(logsByts))
					// 	}
					// }

					errorMsgStr, ok := errorMsg.(string)
					if !ok {
						errorMsgStr = fmt.Sprintf("%s execution failed", ruleName)
					}
					return errors.New(errorMsgStr)
				}

			}

			if _, ok := ruleNameAndAliasInfo[tempRuleNameWithAlias]; ok {
				ruleOutput := ruleOutputs[tempRuleNameWithGroupAndAlias]
				ruleOutput.Outputs = outputs
				byts, err := os.ReadFile(filepath.Join(srcRuleDir, constants.RuleFile))
				if err == nil {
					ruleSet := &vo.RuleSet{}
					err = json.Unmarshal(byts, ruleSet)
					if err == nil && len(ruleSet.Rules) > 0 {
						ruleOutput.Evidences = ruleSet.Rules[0].Evidences
					}
				}

				if outputVariables, ok := additionalInfo.RuleOutputVariableMap[ruleName]; ok {

					for key, val := range outputs {
						validValue := false
						if val != nil {
							switch v := val.(type) {
							case int:
								validValue = true
							case float64:
								validValue = true
							case string:
								if utils.IsNotEmpty(v) {
									validValue = true
								}

							default:

							}
						}

						if validValue {
							outputVariables = utils.FindAndRemoveAllOccurrences(outputVariables, key)
						}

					}

					if len(outputVariables) > 0 {
						ruleOutput.MissingOutputVariables = outputVariables
					}

				}

				ruleOutputs[tempRuleNameWithGroupAndAlias] = ruleOutput
				if ruleOutputsHelper != nil {
					*ruleOutputsHelper = append(*ruleOutputsHelper, ruleOutput)
				}
			}

		}

		taskLevelOutputs, err := getTaskLevelOutputs(tmpRuleDir)

		if err != nil {
			return err
		}

		taskExecutions[ruleName] = taskLevelOutputs

	}

	bar.Add(1)

	return nil
}

func calculateComplianceInfo(outputData map[string]interface{}, additionalInfo *vo.AdditionalInfo) error {

	complianceTaskPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.TasksPath, "CalculateComplianceInfo")

	tempDir := os.TempDir()
	if tempDir == "/tmp" {
		uuid := uuid.New().String()
		tempDir = filepath.Join(tempDir, uuid)
	} else {
		tempDir = filepath.Join(tempDir, "CalculateCompliance")
	}

	defer os.Remove(tempDir)

	err := copy.Copy(complianceTaskPath, tempDir)
	if err != nil {
		return err
	}

	userInputs := &vo.UserInputsVO{}
	userInputs.UserInputs = outputData
	ymlByts, err := yaml.Marshal(userInputs)
	if err != nil {
		return err
	}

	err = os.WriteFile(filepath.Join(tempDir, "inputs.yaml"), ymlByts, os.ModePerm)

	if err != nil {
		return err
	}

	cmd := exec.Command("python3", "-u", "autogenerated_main.py")
	cmd.Dir = tempDir

	_, err = cmd.Output()
	if err != nil {
		return err
	}

	outputFile := filepath.Join(tempDir, "task_output.json")

	fileByts, err := os.ReadFile(outputFile)

	if err != nil {
		return err
	}

	outputs := make(map[string]interface{}, 0)
	additionalInfo.RuleOutputs = map[string]interface{}{}

	err = json.Unmarshal(fileByts, &outputs)
	if err != nil {
		return err
	}

	if taskOutputs, ok := outputs["Outputs"]; ok {
		additionalInfo.RuleOutputs = map[string]interface{}{}
		if taskOutputsMap, ok := taskOutputs.(map[string]interface{}); ok {
			if compliancePCT, ok := taskOutputsMap["CompliancePCT_"]; ok {
				additionalInfo.RuleOutputs["CompliancePCT_"] = compliancePCT
				outputData["CompliancePCT_"] = compliancePCT
			}
			if complianceStatus, ok := taskOutputsMap["ComplianceStatus_"]; ok {
				additionalInfo.RuleOutputs["ComplianceStatus_"] = complianceStatus
				outputData["ComplianceStatus_"] = complianceStatus
			}
		}

	}

	if compliancePCT, ok := outputData["CompliancePCT_"]; ok {
		additionalInfo.RuleOutputs["CompliancePCT_"] = compliancePCT
	}
	if complianceStatus, ok := outputData["ComplianceStatus_"]; ok {
		additionalInfo.RuleOutputs["ComplianceStatus_"] = complianceStatus
	}

	if _, ok := additionalInfo.RuleOutputs["CompliancePCT_"]; !ok {
		additionalInfo.RuleOutputs["CompliancePCT_"] = 0
		additionalInfo.RuleOutputs["ComplianceStatus_"] = "N/A"
	}

	return nil

}

func GetRuleYAML(path string) (*vo.RuleYAMLVO, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ruleYaml *vo.RuleYAMLVO
	err = yaml.Unmarshal(file, &ruleYaml)
	return ruleYaml, err
}

func GetRuleSetFromYAML(path string) (*vo.RuleSet, error) {

	ruleYaml, err := GetRuleYAML(path)
	if err != nil {
		return nil, err
	}
	if len(ruleYaml.Meta.Labels) == 0 {
		return nil, fmt.Errorf("invalid rule yaml. Primary ApplicationType is not present in the rule")
	}

	ruleTags := map[string][]string{
		"environment": {"logical"},
		"execlevel":   {"app"},
	}

	maps.Copy(ruleTags, ruleYaml.Meta.Labels)

	rule := vo.Rule{
		RuleBase: vo.RuleBase{
			RuleName:    ruleYaml.Meta.Name,
			Purpose:     ruleYaml.Meta.Purpose,
			Description: ruleYaml.Meta.Description,
			AliasRef:    ruleYaml.Meta.AliasRef,
			RuleType:    "sequential",
		},
		RuleTags: ruleTags,
		RuleIOValues: &vo.IOValues{
			Inputs: nil,
		},
		TasksInfo: make([]interface{}, 0, len(ruleYaml.Spec.Tasks)),
		RefMaps:   []*vo.RefStruct{},
	}
	DefaultInputs := make(map[string]interface{}, len(ruleYaml.Spec.Input))
	for key, val := range ruleYaml.Spec.Input {
		DefaultInputs[key] = val
	}
	rule.RuleIOValues.Inputs = DefaultInputs

	rule.RuleIOValues.InputsMeta__ = ruleYaml.Spec.InputsMeta__
	rule.RuleIOValues.OutputsMeta__ = ruleYaml.Spec.OutputsMeta__

	for _, input := range rule.RuleIOValues.InputsMeta__ {
		if inputMap, ok := input.DefaultValue.(map[interface{}]interface{}); ok {
			input.DefaultValue = utils.ConvertMap(inputMap)
		}
	}

	for _, taskInfo := range ruleYaml.Spec.Tasks {
		rule.TasksInfo = append(rule.TasksInfo, &vo.TaskInfo{
			TaskBase: vo.TaskBase{
				Type:        "task",
				TaskGUID:    "{{" + taskInfo.Name + "}}",
				Purpose:     taskInfo.Purpose,
				Description: taskInfo.Description,
				AliasRef:    taskInfo.Alias,
				AppTags:     taskInfo.AppTags,
			},
		})
	}

	compliancePCTPresent, complianceStatusPresent := false, false

	inputs := make(map[string]interface{}, 0)

	targetOutputVariables := make([]string, 0)
	srcInputVariables := make([]string, 0)

	selfAssignVars := make([]string, 0)
	incorrectFormatErrors := make([]string, 0)
	sourceRefFormatErrors := make([]string, 0)
	targetRefFormatErrors := make([]string, 0)
	inValidFieldTypes := make([]string, 0)

	for _, iomap := range ruleYaml.Spec.IoMap {
		iomapArr := strings.Split(iomap, ":=")

		if len(iomapArr) < 2 {
			incorrectFormatErrors = append(incorrectFormatErrors, fmt.Sprintf("'%s'", iomap))
			continue
		}
		targetArr := strings.Split(iomapArr[0], ".")
		if len(targetArr) < 3 {
			targetRefFormatErrors = append(targetRefFormatErrors, fmt.Sprintf("'%s'", iomap))
			continue
		}
		sourceArr := strings.Split(iomapArr[1], ".")
		if len(sourceArr) < 3 {
			sourceRefFormatErrors = append(sourceRefFormatErrors, fmt.Sprintf("'%s'", iomap))
			continue
		}

		if sourceArr[0] == "*" && sourceArr[1] == "Input" {
			inputs[sourceArr[2]] = nil
		}

		if sourceArr[0] == targetArr[0] && sourceArr[1] == targetArr[1] && sourceArr[2] == targetArr[2] {
			selfAssignVars = append(selfAssignVars, fmt.Sprintf("'%s'", targetArr[2]))
			continue
		}

		if targetArr[1] == "Input" && targetArr[0] == "*" {
			targetOutputVariables = append(targetOutputVariables, fmt.Sprintf("'%s'", targetArr[2]))
			continue
		}

		if sourceArr[1] == "Output" && sourceArr[0] == "*" {
			srcInputVariables = append(srcInputVariables, fmt.Sprintf("'%s'", sourceArr[2]))
			continue
		}

		fieldTypes := []string{"Input", "Output"}

		if !utils.SliceContains(fieldTypes, sourceArr[1]) || !utils.SliceContains(fieldTypes, targetArr[1]) {
			inValidFieldTypes = append(inValidFieldTypes, iomap)
		}

		rule.RefMaps = append(rule.RefMaps, &vo.RefStruct{
			SourceRef: vo.FieldMap{
				AliasRef:  sourceArr[0],
				FieldType: sourceArr[1],
				VarName:   sourceArr[2],
			},
			TargetRef: vo.FieldMap{
				AliasRef:  targetArr[0],
				FieldType: targetArr[1],
				VarName:   targetArr[2],
			},
		})

		if targetArr[2] == "CompliancePCT_" {
			compliancePCTPresent = true
		}

		if targetArr[2] == "ComplianceStatus_" {
			complianceStatusPresent = true
		}

	}

	if len(inputs) > 0 {
		rule.RuleIOValues.Inputs = inputs
	}

	errorMsgs := make([]string, 0)

	if len(targetOutputVariables) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Assigning the output variable {%s} as input to the flow is not allowed.", strings.Join(targetOutputVariables, ",")))
	}

	if len(srcInputVariables) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("You cannot use the output variable of the rule as an input. {%s}", strings.Join(srcInputVariables, ",")))
	}

	if len(selfAssignVars) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Cannot assign a variable to itself. {%s}", strings.Join(selfAssignVars, ",")))
	}

	if len(incorrectFormatErrors) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("The provided mappings are incorrect. {%s}", strings.Join(incorrectFormatErrors, ",")))
	}

	if len(sourceRefFormatErrors) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Invalid source format. {%s}", strings.Join(sourceRefFormatErrors, ",")))
	}

	if len(targetRefFormatErrors) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Invalid target format. {%s}", strings.Join(targetRefFormatErrors, ",")))
	}

	if len(inValidFieldTypes) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Invalid field types. {%s}", strings.Join(inValidFieldTypes, ",")))
	}

	if !compliancePCTPresent && !complianceStatusPresent {
		errorMsgs = append(errorMsgs, "The output mapping should include variables for compliance percentage and compliance status.")
	}

	if !compliancePCTPresent {
		errorMsgs = append(errorMsgs, "Please include a variable in the output mapping that represents the compliance percentage.")
	}

	if !complianceStatusPresent {
		errorMsgs = append(errorMsgs, "Please include a variable in the output mapping that represents the compliance status.")
	}

	if len(errorMsgs) > 0 {

		if len(errorMsgs) == 1 {
			return nil, errors.New(errorMsgs[0])
		}

		orderedErrorMsgs := make([]string, 0)

		for i, errorMsg := range errorMsgs {
			orderedErrorMsgs = append(orderedErrorMsgs, fmt.Sprintf("%d. %s", i+1, errorMsg))
		}

		return nil, errors.New(strings.Join(orderedErrorMsgs, "\n"))
	}

	ruleSet := vo.RuleSet{Rules: []*vo.Rule{&rule}}
	return &ruleSet, nil
}

func getTaskLevelOutputs(rulePath string) (map[string]map[string]interface{}, error) {
	taskOutputsMap := make(map[string]map[string]interface{}, 0)
	if taskOutputsJSONFilePath := filepath.Join(rulePath, "task_level_output.json"); utils.IsFileExist(taskOutputsJSONFilePath) {
		fileByts, err := os.ReadFile(taskOutputsJSONFilePath)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(fileByts, &taskOutputsMap)
		if err != nil {
			return nil, err
		}
	}
	return taskOutputsMap, nil
}

func handleRuleInputs(rulePath, ruleName, ruleNameWithGroup string, ruleOutputs map[string]*vo.RuleOutputs, ruleDependency *vo.RuleDependency,
	ruleNameAndAliasInfo map[string]string, additionalInfo *vo.AdditionalInfo, isBinaryToBeCreated bool, ruleInfo *vo.RuleInfo, srcRuleName string, isExecuteCall bool) {

	if ruleDependency != nil {

		ruleGroup := ``

		if utils.IsNotEmpty(ruleDependency.RuleGroup) {
			ruleGroup = "_" + ruleDependency.RuleGroup
		}

		inputs := make(map[string]interface{}, 0)

		userInputs := make(map[string]interface{}, 0)
		if ruleDependency.Inputs != nil && len(ruleDependency.Inputs.UserInputs) > 0 {
			userInputs = ruleDependency.Inputs.UserInputs
		}

		if aliasRef, ok := ruleNameAndAliasInfo[ruleName]; ok {

			for _, ref := range ruleDependency.RefMap {

				if utils.IsNotEmpty(ref.SourceRef.AliasRef) && ref.SourceRef.AliasRef == "*" {
					if val, ok := userInputs[ref.SourceRef.VarName]; ok {
						inputs[ref.TargetRef.VarName] = val
					}
				}

				if ref.TargetRef.AliasRef == aliasRef && utils.IsNotEmpty(ref.SourceRef.AliasRef) {

					if srcRuleName, ok := ruleNameAndAliasInfo[ref.SourceRef.AliasRef]; ok {
						if output, ok := ruleOutputs[srcRuleName+ruleGroup+"-"+ref.SourceRef.AliasRef]; ok {
							if val, isPresent := output.Outputs[ref.SourceRef.VarName]; isPresent {
								inputs[ref.TargetRef.VarName] = val
							}
						}
					}

				}

			}

		}

		if isRulePath(rulePath) {
			ruleJSONPath := filepath.Join(rulePath, constants.RuleFile)
			byts, err := os.ReadFile(ruleJSONPath)
			if err != nil {
				// TOD0: handle error
			}
			ruleSet := &vo.RuleSet{}
			err = json.Unmarshal(byts, ruleSet)
			if err == nil {
				if len(ruleSet.Rules) > 0 {
					rule := ruleSet.Rules[0]

					additionalInfo.ValidationErrors = utils.ValidateRefMap(rule.RefMaps)

					outputVariables := make([]string, 0)
					if rule.RefMaps != nil {
						for _, refMap := range rule.RefMaps {

							if refMap.TargetRef.AliasRef == "*" && utils.IsNotEmpty(refMap.TargetRef.VarName) {
								outputVariables = append(outputVariables, refMap.TargetRef.VarName)
							}
						}
					}
					if additionalInfo.RuleOutputVariableMap == nil {
						additionalInfo.RuleOutputVariableMap = make(map[string][]string, 0)
					}
					additionalInfo.RuleOutputVariableMap[srcRuleName] = outputVariables
				}

				err := copyTaskFoldersInToRulePath(rulePath, ruleSet, additionalInfo, isBinaryToBeCreated, isExecuteCall)
				if err != nil {
				}

				if ruleInfo != nil && len(ruleInfo.UserInputs) > 0 {

					for key, val := range inputs {
						if val == "http://" || val == "hash" {
							delete(inputs, key)
						}
					}

					maps.Copy(inputs, ruleInfo.UserInputs)
				}

				if len(inputs) > 0 {
					rule := ruleSet.Rules[0]
					ruleInputs := rule.RuleIOValues.Inputs

					if ruleInputs == nil {
						ruleInputs = make(map[string]interface{}, 0)
					}

					for key, val := range inputs {
						if key != "CompliancePCT_" && key != "ComplianceStatus_" {
							ruleInputs[key] = val
						}
					}

					rule.RuleIOValues.Inputs = ruleInputs
					ruleSet.Rules[0] = rule
					ruleSet.PlanExecutionGUID = additionalInfo.ExecutionID
					fileByts, err := json.MarshalIndent(ruleSet, "", "	")
					if err == nil {
						os.WriteFile(ruleJSONPath, fileByts, os.ModePerm)
					}
				}

			}

			inputsFilePath := filepath.Join(rulePath, constants.TaskInputYAMLFile)

			yamlInputByts, err := os.ReadFile(inputsFilePath)
			yamlTaskInputMap := make(map[string]interface{}, 0)
			if err == nil {
				yaml.Unmarshal(yamlInputByts, &yamlTaskInputMap)
				if val, ok := yamlTaskInputMap["userInputs"]; ok {

					userInputsMapIn := make(map[string]interface{}, 0)

					if userInputsMap, ok := val.(map[interface{}]interface{}); ok {
						for key, value := range userInputsMap {

							keyAsStr, ok := key.(string)
							if ok {
								if val, ok := inputs[keyAsStr]; ok {
									userInputsMapIn[keyAsStr] = val
								} else {
									userInputsMapIn[keyAsStr] = value
								}
							}
						}
					}

					userInputsMap, ok := val.(map[string]interface{})
					if ok {
						for key, value := range userInputsMap {

							if val, ok := inputs[key]; ok {
								userInputsMapIn[key] = val
							} else {
								userInputsMapIn[key] = value
							}

						}
					}

					yamlTaskInputMap["userInputs"] = userInputsMapIn

					if ruleDependency.Inputs != nil {

						if utils.IsNotEmpty(ruleDependency.Inputs.FromDate_) {
							yamlTaskInputMap["fromDate"], _ = time.Parse("2006-01-02", ruleDependency.Inputs.FromDate_)
						}

						if utils.IsNotEmpty(ruleDependency.Inputs.ToDate_) {
							yamlTaskInputMap["toDate"], _ = time.Parse("2006-01-02", ruleDependency.Inputs.ToDate_)
						}
					}

					var yamlInput vo.TaskInputV2
					err = yaml.Unmarshal(yamlInputByts, &yamlInput)
					if err != nil {
						fmt.Println("Error unmarshaling YAML:", err)
					}

					if userInputs, ok := yamlTaskInputMap["userInputs"].(map[string]interface{}); ok {
						yamlInput.UserInputs = userInputs
					}

					updatedYAMLInputBytes, err := yaml.Marshal(&yamlInput)
					if err == nil {
						os.WriteFile(inputsFilePath, updatedYAMLInputBytes, os.ModePerm)
					}

				}
			}
		}

	}

}

func replaceLibraryPathsInGoMod(goModFilePath string, additionalInfo *vo.AdditionalInfo) error {

	if !strings.HasSuffix(goModFilePath, string(os.PathSeparator)+"go.mod") {
		goModFilePath = filepath.Join(goModFilePath, "go.mod")
	}

	byts, err := os.ReadFile(goModFilePath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(byts), "\n")
	for i, line := range lines {

		// TODO: Check the replace clause
		if strings.Contains(line, "applicationtypes") && !strings.Contains(line, "applicationtypes v") {
			lines[i] = ""
		}
		if strings.Contains(line, "cowlibrary") && !strings.Contains(line, "cowlibrary v") {
			lines[i] = ""
		}
	}
	applicationTypesPath := "/policycow/catalog/applicationtypes/go"
	cowlibraryPath := "/policycow/src/cowlibrary"
	if utils.IsFolderExist(additionalInfo.PolicyCowConfig.PathConfiguration.ExecutionPath) {
		repoPath := removeLastSubFolder(additionalInfo.PolicyCowConfig.PathConfiguration.ExecutionPath)
		if utils.IsFolderExist(repoPath) {
			if appPath := filepath.Join(repoPath, "catalog/applicationtypes/go"); utils.IsFolderExist(appPath) {
				applicationTypesPath = filepath.Join(repoPath, "catalog/applicationtypes/go")
			}
			if libPath := filepath.Join(repoPath, "src/cowlibrary"); utils.IsFolderExist(libPath) {
				cowlibraryPath = filepath.Join(repoPath, "src/cowlibrary")
			}
		}
	}
	lines = append(lines, fmt.Sprintf("replace applicationtypes => %s", applicationTypesPath))
	lines = append(lines, fmt.Sprintf("replace cowlibrary => %s", cowlibraryPath))

	fileContent := []byte(strings.Join(lines, "\n"))
	err = os.WriteFile(goModFilePath, fileContent, 0644)
	if err != nil {
		return err
	}

	return err
}

func removeLastSubFolder(path string) string {
	cleanedPath := filepath.Clean(path)
	dir, _ := filepath.Split(cleanedPath)

	return filepath.Clean(dir)
}

func copyTaskFoldersInToRulePath(rulePath string, ruleSet *vo.RuleSet, additionalInfo *vo.AdditionalInfo, isBinaryToBeCreated bool, isExecuteCall bool) error {

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

			sort.Slice(taskInfos[:], func(i, j int) bool {
				return taskInfos[i].SeqNo < taskInfos[j].SeqNo
			})

			ruleMainFileData := strings.NewReplacer("{{Task_VO}}", constants.TaskVO, "{{Task_Server_Struct}}", constants.TaskServerStructs).Replace(constants.RuleMainFileData)

			if err := os.WriteFile(filepath.Join(rulePath, constants.AutoGeneratedFilePrefix+"main.go"), []byte(ruleMainFileData), os.ModePerm); err != nil {
				fmt.Println("error occurs :", err)
			}

			for _, task := range taskInfos {
				taskName := strings.NewReplacer("{{", "", "}}", "").Replace(task.TaskGUID)
				tasksNewFolder := filepath.Join(rulePath, taskName)
				if isExecuteCall {
					tasksNewFolder = filepath.Join(rulePath, taskName+"-"+task.AliasRef)
				}

				opt := cp.Options{
					Skip: func(srcInfo fs.FileInfo, src string, dest string) (bool, error) {
						pathArr := strings.Split(src, string(os.PathSeparator))
						isFilesFolder := false

						if len(pathArr) > 0 {
							isFilesFolder = pathArr[len(pathArr)-1] == "files"
						}
						return strings.HasSuffix(src, "task_output.json") || strings.HasSuffix(src, "task_input.json") || strings.HasSuffix(src, constants.TaskInputYAMLFile) || isFilesFolder, nil
					},
				}
				ruleName := filepath.Base(rulePath)
				taskPath := utils.GetTaskPathFromCatalog(additionalInfo, ruleName, taskName)
				if utils.IsEmpty(taskPath) {
					return fmt.Errorf("could not find task at : %s", taskPath)

				}
				err := cp.Copy(taskPath, tasksNewFolder, opt)
				if err != nil {
					fmt.Println("folder copy error happens")
					return fmt.Errorf("error happens : %s", err.Error())
				}
				// if inputs.yaml in rulepath- copy it to task folder
				if utils.IsFileExist(filepath.Join(rulePath, constants.TaskInputYAMLFile)) {
					ruleInputYAMLBytes, err := os.ReadFile(filepath.Join(rulePath, constants.TaskInputYAMLFile))
					if err != nil {
						return fmt.Errorf("failed to read rule inputs.yaml: %s", err)
					}
					var taskInput vo.TaskInputV2
					err = yaml.Unmarshal(ruleInputYAMLBytes, &taskInput)
					if err != nil {
						return fmt.Errorf("error unmarshalling taskInput.yaml: %s", err)
					}

					if taskInput.UserObject != nil && taskInput.UserObject.Apps != nil {
						ruleYAMLBytes, err := os.ReadFile(filepath.Join(rulePath, constants.RuleYamlFile))
						if err != nil {
							return fmt.Errorf("failed to read rule.yaml: %s", err)
						}
						var rule vo.RuleYAMLVO
						err = yaml.Unmarshal(ruleYAMLBytes, &rule)
						if err != nil {
							return fmt.Errorf("error unmarshalling rule.yaml: %s", err)
						}

						var selectedApp *vo.AppAbstract
						for _, app := range taskInput.UserObject.Apps {
							if app != nil && reflect.DeepEqual(app.AppTags, task.AppTags) {
								selectedApp = app
								break
							}
						}

						taskInput.UserObject.App = selectedApp
						taskInput.UserObject.Apps = nil
						updatedTaskInputYAML, err := yaml.Marshal(&taskInput)
						if err != nil {
							return fmt.Errorf("error marshalling updated taskInput.yaml: %w", err)
						}
						err = os.WriteFile(filepath.Join(tasksNewFolder, constants.TaskInputYAMLFile), updatedTaskInputYAML, os.ModePerm)
						if err != nil {
							return fmt.Errorf("error writing updated taskInput.yaml: %w", err)
						}

					} else {
						cp.Copy(filepath.Join(rulePath, constants.TaskInputYAMLFile), filepath.Join(tasksNewFolder, constants.TaskInputYAMLFile), opt)
					}
				}

				for _, val := range ruleSet.Rules[0].RuleIOValues.Inputs {
					if strVal, ok := val.(string); ok && strings.HasPrefix(strVal, "file://") {
						fileName := filepath.Base(strVal)
						taskFilePath := filepath.Join(taskPath, constants.LocalFolder, fileName)
						ruleFilePath := filepath.Join(rulePath, constants.LocalFolder, fileName)
						catalogFilePath := filepath.Join(taskPath, "../../", constants.LocalFolder, fileName)

						if utils.IsFileNotExist(taskFilePath) {
							userdataDir := filepath.Join(tasksNewFolder, constants.LocalFolder)
							if err := os.MkdirAll(userdataDir, os.ModePerm); err != nil {
								fmt.Printf("Error creating userdata directory: %v\n", err)
							}
							localpath := filepath.Join(userdataDir, fileName)
							var sourcePath string
							if utils.IsFileExist(ruleFilePath) {
								sourcePath = ruleFilePath
							} else if utils.IsFileExist(catalogFilePath) {
								sourcePath = catalogFilePath
							} else {
								fmt.Printf("%s file is not present in the system", fileName)
								continue
							}

							if err := cp.Copy(sourcePath, localpath); err != nil {
								return err
							}
						}
					}
				}

				replaceLibraryPathsInGoMod(tasksNewFolder, additionalInfo)

				if !utils.IsGoTask(tasksNewFolder) {
					appConnPath := additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationTypesPath
					err := cp.Copy(filepath.Join(appConnPath, "python", filepath.Base(appConnPath)), filepath.Join(tasksNewFolder, filepath.Base(appConnPath)))
					if err != nil {
						return err
					}
					cp.Copy(filepath.Join(appConnPath, "python", "requirements.txt"), filepath.Join(tasksNewFolder, filepath.Base(appConnPath), "requirements.txt"))
				}

				if err == nil && isBinaryToBeCreated && utils.IsGoTask(tasksNewFolder) {
					commandSeq := ``
					if _, err := os.Stat(filepath.Join(tasksNewFolder, "go.mod")); os.IsNotExist(err) {
						commandSeq += fmt.Sprintf("go mod init  %s && ", taskName)
					} else {
						commandSeq += fmt.Sprintf("go mod edit -module %s && ", taskName)
					}

					commandSeq += `go mod tidy && go build -a -installsuffix cgo -o ` + taskName

					cmd := exec.Command("bash", "-c", commandSeq)
					cmd.Env = append(os.Environ(), []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64"}...)
					cmd.Dir = filepath.Join(rulePath, taskName)
					_, err := cmd.Output()
					if err != nil {
						return err
					}
				}

			}
		}

	}

	return nil
}

func PrepareRule(path, ruleExp string, includeRules, excludeRules []string, isTasksToBePrepare bool, additionalInfo *vo.AdditionalInfo) error {
	directoryPath := ``
	if stringUtils.IsEmpty(path) {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		path = wd
	}
	if utils.IsNotEmpty(path) {

		fileInfo, err := os.Stat(path)
		if os.IsNotExist(err) || !fileInfo.IsDir() {
			return errors.New("not a valid path")
		}

		if stringUtils.IsNotBlank(path) {
			if strings.HasSuffix(path, "/") {
				path = path[:len(path)-1]
			}

		}

		directoryPath = path

	}

	return filepath.WalkDir(directoryPath, func(path string, info fs.DirEntry, e error) error {
		if e != nil {
			return e
		}

		if info.IsDir() {
			if isRulePath(path) {
				err := prepRuleHelper(path, isTasksToBePrepare, additionalInfo)

				if err != nil {
					return err
				}
			}
		}
		return nil
	})

}

func prepRuleHelper(rulePath string, isTasksToBePrepare bool, additionalInfo *vo.AdditionalInfo) error {

	if isTasksToBePrepare {

		tasksFolder := additionalInfo.PolicyCowConfig.PathConfiguration.TasksPath

		if stringUtils.IsEmpty(tasksFolder) || !utils.IsFileExist(tasksFolder) {
			return errors.New("not a valid task path")
		}

		ruleJSONPath := filepath.Join(rulePath, constants.RuleFile)

		if utils.IsFileNotExist(ruleJSONPath) {
			return errors.New("not a valid rule path. rule.json is missing")
		}

		ruleJSONByts, err := os.ReadFile(ruleJSONPath)
		if err != nil {
			return err
		}

		ruleSet := &vo.RuleSet{}
		err = json.Unmarshal(ruleJSONByts, ruleSet)
		if err != nil {
			return err
		}

		if ruleSet.Rules != nil && len(ruleSet.Rules) > 0 {
			for _, rule := range ruleSet.Rules {

				taskBases := make([]*vo.TaskBase, 0)
				if rule.TasksInfo != nil {
					byts, err := json.Marshal(rule.TasksInfo)
					if err != nil {
						return err
					}

					err = json.Unmarshal(byts, &taskBases)
					if err != nil {
						return err
					}

					for _, taskBase := range taskBases {
						if utils.IsNotEmpty(taskBase.TaskGUID) {
							taskName := strings.NewReplacer("{{", "", "}}", "").Replace(taskBase.TaskGUID)

							if taskPath := filepath.Join(tasksFolder, taskName); utils.IsFolderExist(taskPath) && isValidTaskFolder(taskPath) {
								language := utils.GetTaskLanguage(taskPath)
								languageSpecificTask := task.GetTask(language)
								err := languageSpecificTask.PrepareTask(taskPath, additionalInfo)
								if err != nil {
									return err
								}
							}

						}
					}
				}

			}
		}

	}

	return nil
}

func isValidTaskFolder(taskPath string) bool {

	if !strings.HasSuffix(taskPath, string(os.PathSeparator)) {
		taskPath += string(os.PathSeparator)
	}

	filePath := taskPath + "task_service.go"
	if _, err := os.Stat(filePath); err == nil {
		return true
	}
	filePath = taskPath + "task.py"
	if _, err := os.Stat(filePath); err == nil {
		return true
	}
	return false
}

type FileInfo struct {
	Name        string `json:"name"`
	FileHash    string `json:"fileHash"`
	FilePath    string `json:"filePath"`
	FileContent []byte `json:"fileContent"`
}

type RunSummary struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	ExecutedAt  *time.Time        `json:"executedAt"`
	RuleOutputs []*vo.RuleOutputs `json:"ruleOutputs"`
	FileInfos   []*FileInfo       `json:"fileInfos"`
}

func DrawSummaryTable(ruleOutputs []*vo.RuleOutputs, additionalInfo *vo.AdditionalInfo) {
	NotAvailable := "N/A"

	table := tablewriter.NewWriter(os.Stdout)
	table.SetRowLine(true)

	table.SetHeader([]string{"Rule Name", "Alias Ref", "Rule Group", "Status", "Compliance %", "Remarks"})

	table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgYellowColor})

	evidenceTable := tablewriter.NewWriter(os.Stdout)
	evidenceTable.SetHeader([]string{"Rule Name", "Evidence Name", "Compliance Weight", "Compliance Status", "Compliance %"})
	evidenceTable.SetHeaderColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor})

	var count float64 = 0

	var sumOfPCT float64 = 0

	hasEvidences := false

	isNonCompliant := false
	cumPCT, cumWeight, evidenceCount := 0.0, 0, 0

	availableStatuses := []string{constants.ComplianceStatusCompliant, constants.ComplianceStatusNonCompliant, constants.ComplianceStatusNotDetermined}

	for _, ruleOutput := range ruleOutputs {
		row := []string{ruleOutput.RuleName, ruleOutput.AliasRef, ruleOutput.RuleGroup}

		remarksMsgs := make([]string, 0)

		complianceStatus, isStatusAvailable := ruleOutput.Outputs["ComplianceStatus_"].(string)
		if isStatusAvailable {
			if !utils.SliceContains(availableStatuses, complianceStatus) {
				remarksMsgs = append(remarksMsgs, fmt.Sprintf("invalid compliance status '%s'", complianceStatus))
			}
			row = append(row, complianceStatus)
		} else {
			row = append(row, NotAvailable)
		}

		var compliancePCT float64 = 0

		if val, ok := ruleOutput.Outputs["CompliancePCT_"]; ok {
			compPCT, isValidCasting := val.(float64)
			compliancePCT = compPCT
			if isValidCasting {
				// compliancePCTStr := NotAvailable
				if compliancePCT < 0 {
					remarksMsgs = append(remarksMsgs, fmt.Sprintf("compliance pct cannot be less than 0 '%.0f'", compliancePCT))
				} else if compliancePCT > 100 {
					remarksMsgs = append(remarksMsgs, fmt.Sprintf("compliance pct cannot be lesser or equal to 100 '%.0f'", compliancePCT))
				}
				// else if compliancePCT <= 100 && compliancePCT >= 0 {
				count++
				sumOfPCT += compliancePCT
				row = append(row, fmt.Sprintf("%.2f", compliancePCT))
				// compliancePCTStr = fmt.Sprintf("%.2f", compliancePCT)
				// }
				// row = append(row, compliancePCTStr)
			} else {
				row = append(row, NotAvailable)
			}

		} else {
			row = append(row, NotAvailable)
		}

		if utils.SliceContains(availableStatuses, complianceStatus) && compliancePCT <= 100 && compliancePCT >= 0 {

			if complianceStatus == constants.ComplianceStatusCompliant {
				if compliancePCT < 100 {
					remarksMsgs = append(remarksMsgs, fmt.Sprintf("compliance pct should be '100' for compliance status '%s'", constants.ComplianceStatusCompliant))
				}
			}

			if complianceStatus == constants.ComplianceStatusNonCompliant {
				if compliancePCT == 100 {
					remarksMsgs = append(remarksMsgs, fmt.Sprintf("compliance pct should be lesser than '100' for compliance status '%s'", constants.ComplianceStatusNonCompliant))
				}
			}

			if complianceStatus == constants.ComplianceStatusNotDetermined {
				if compliancePCT > 0 {
					remarksMsgs = append(remarksMsgs, fmt.Sprintf("compliance pct should be '0' for compliance status '%s'", constants.ComplianceStatusNotDetermined))
				}
			}

		}

		remarksColour := tablewriter.Colors{}

		if len(ruleOutput.MissingOutputVariables) > 0 {
			msg := fmt.Sprintf("Variables {%s} are absent in the output", strings.Join(ruleOutput.MissingOutputVariables, ", "))
			remarksMsgs = append(remarksMsgs, msg)
			remarksColour = tablewriter.Colors{tablewriter.Bold}
		}

		if len(remarksMsgs) > 0 {

			remarksMsg := ``

			for i, msg := range remarksMsgs {
				formatter := "%d. %s"
				if i != len(remarksMsgs)-1 {
					formatter += ", "
				}
				remarksMsg += fmt.Sprintf(formatter, i+1, msg)
			}

			row = append(row, remarksMsg)

		} else {
			row = append(row, "")
		}

		if complianceStatus == constants.ComplianceStatusCompliant {
			table.Rich(row, []tablewriter.Colors{tablewriter.Colors{}, tablewriter.Colors{}, tablewriter.Colors{}, tablewriter.Colors{tablewriter.Bold, tablewriter.FgGreenColor}, tablewriter.Colors{}, remarksColour})
		} else {
			table.Rich(row, []tablewriter.Colors{tablewriter.Colors{}, tablewriter.Colors{}, tablewriter.Colors{}, tablewriter.Colors{tablewriter.Bold, tablewriter.FgRedColor}, tablewriter.Colors{}, remarksColour})
		}

		if !hasEvidences && len(ruleOutput.Evidences) > 0 {
			hasEvidences = true
		}

		for _, evidence := range ruleOutput.Evidences {

			evidenceName := evidence.Name

			evidenceRow := []string{ruleOutput.RuleName, evidenceName, strconv.Itoa(int(evidence.ComplianceWeight__)), evidence.ComplianceStatus__, strconv.Itoa(int(evidence.CompliancePCT__))}

			evidenceComplinaceWeight := int(evidence.ComplianceWeight__)
			evidenceComplinaceStatus := evidence.ComplianceStatus__
			evidenceComplinacecPCT := evidence.CompliancePCT__

			if !isNonCompliant && (evidenceComplinaceStatus == "Not Compliant" || evidenceComplinaceStatus == "Non Compliance" || evidenceComplinaceStatus == "Non Compliant") {
				isNonCompliant = true
			}

			if evidenceComplinacecPCT == 100 || evidenceComplinaceStatus == "Compliant" || evidenceComplinaceStatus == "Compliance" {
				evidenceRow[3] = "Compliance"
				evidenceTable.Rich(evidenceRow, []tablewriter.Colors{tablewriter.Colors{}, tablewriter.Colors{}, tablewriter.Colors{}, tablewriter.Colors{tablewriter.Bold, tablewriter.FgGreenColor}, tablewriter.Colors{}})
			} else {
				evidenceTable.Rich(evidenceRow, []tablewriter.Colors{tablewriter.Colors{}, tablewriter.Colors{}, tablewriter.Colors{}, tablewriter.Colors{tablewriter.Bold, tablewriter.FgRedColor}, tablewriter.Colors{}})
			}

			if evidenceComplinaceStatus != "Not Determined" {
				if evidenceComplinaceWeight > 0 {
					evidenceCount += 1
				}

				cumPCT += float64(evidenceComplinaceWeight) * evidenceComplinacecPCT
				cumWeight += evidenceComplinaceWeight
			}

		}

	}

	overrallPCT := sumOfPCT / count

	table.SetFooter([]string{"", "", "", "Total", fmt.Sprintf("%.2f", overrallPCT), "-"}) // Add Footer
	table.SetFooterColor(tablewriter.Colors{}, tablewriter.Colors{}, tablewriter.Colors{},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.FgHiRedColor}, tablewriter.Colors{tablewriter.Bold})

	if hasEvidences {
		fmt.Println("Below table shows infos about evidences..!")
		cumPCT = math.Round(cumPCT / float64(cumWeight))
		cumWeight = cumWeight / evidenceCount
		evidenceOverAllStatus := "Not Determined"
		if evidenceCount > 0 {
			evidenceOverAllStatus = "Compliance"
			if isNonCompliant {
				evidenceOverAllStatus = "Non Compliance"
			}
		}
		evidenceTable.SetFooter([]string{"", "Summary", fmt.Sprintf("%d", cumWeight), evidenceOverAllStatus, fmt.Sprintf("%.2f", cumPCT)}) // Add Footer
		evidenceTable.SetFooterColor(tablewriter.Colors{},
			tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiBlueColor},
			tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiBlueColor},
			tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiBlueColor},
			tablewriter.Colors{tablewriter.FgHiRedColor})
		evidenceTable.SetAutoMergeCellsByColumnIndex([]int{0, 1})
		evidenceTable.SetRowLine(true)
		evidenceTable.SetCaption(true, "** N/A will be excluded for calculating total percentage.")
		evidenceTable.Render()
	} else {
		tableCaption := "** N/A will be excluded for calculating total percentage."
		table.SetCaption(true, tableCaption)
		table.Render()
	}

	d := color.New(color.FgCyan, color.Bold)

	for _, ruleOutput := range ruleOutputs {
		var links []string
		if ruleOutput != nil && len(ruleOutput.Outputs) > 0 {
			d.Println("\nYou can view the minio file outputs here")
			for key, value := range ruleOutput.Outputs {
				minioLoginURL := utils.Getenv(constants.EnvMinioLoginURL, "cowstorage:9000")
				if str, ok := value.(string); ok {
					if strings.Contains(str, minioLoginURL) {
						splitPath := strings.Split(str, "/")
						bucketName := splitPath[3]
						fileName := strings.TrimSuffix(path.Base(str), path.Ext(path.Base(str)))
						filePathParts := splitPath[4 : len(splitPath)-1]
						filePath := strings.Join(filePathParts, "/")
						minioURL := "http://localhost:9001/browser/" + bucketName + "/" + filePath + "/" + fileName
						link := utils.ColorLink(key, minioURL, "italic green")
						links = append(links, link)
					} else if cowStorage.IsAmazonS3Host(str) {
						link := utils.ColorLink(key, str, "italic green")
						links = append(links, link)
					}
				}
			}
			urlLinks := strings.Join(links, ", ")
			d := color.New(color.FgCyan, color.FgYellow)
			d.Println(ruleOutput.RuleName + " - " + urlLinks + "\n")
		}
	}
}

func CreateRuleWithYAML(yamlFilePath string, additionalInfo *vo.AdditionalInfo) error {
	yamlFile, err := os.ReadFile(yamlFilePath)
	if err != nil {
		return err
	}

	var ruleFlow vo.RuleFlow
	err = yaml.Unmarshal(yamlFile, &ruleFlow)
	if err != nil {
		return err
	}

	s := spinner.New(spinner.CharSets[43], 100*time.Millisecond)
	s.Start()

	defer s.Stop()

	if utils.IsNotEmpty(ruleFlow.Spec.RulesFolderPath) {
		additionalInfo.PolicyCowConfig.PathConfiguration.RulesPath = ruleFlow.Spec.RulesFolderPath
	} else if utils.IsNotEmpty(additionalInfo.PolicyCowConfig.PathConfiguration.RulesPath) {
		ruleFlow.Spec.RulesFolderPath = additionalInfo.PolicyCowConfig.PathConfiguration.RulesPath
	}

	directoryPath, err := utils.GetRulePath(ruleFlow.Spec.RulesFolderPath, ruleFlow.Metadata.Name)
	if err != nil {
		return errors.New("not a valid path")
	}

	_, err = os.Stat(directoryPath)
	if os.IsNotExist(err) {
		if err = os.MkdirAll(directoryPath, os.ModePerm); err != nil {
			return errors.New("not a valid path")
		}
	}

	if err != nil {
		return err
	}

	ruleSet, taskFlows := getRuleSet(ruleFlow, directoryPath)

	ruleByts, err := json.Marshal(ruleSet)

	if err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(directoryPath, constants.RuleFile), ruleByts, os.ModePerm); err != nil {
		return err
	}

	err = prepRuleHelper(directoryPath, false, additionalInfo)

	if err != nil {
		return err
	}

	taskErrors := make([]*vo.PolicyCowError, 0)

	for _, taskFlow := range taskFlows {
		taskFlow.Spec.RulePath = directoryPath
		languageSpecificTask, err := task.GetTaskFromLanguage(taskFlow.Spec.Language)
		if err != nil {
			return err
		}
		err = languageSpecificTask.CreateTaskWithYAMLStruct(*taskFlow, taskFlow.Spec.RulePath, additionalInfo)
		if err != nil {
			taskErrors = append(taskErrors, &vo.PolicyCowError{Type: "task", Name: taskFlow.Metadata.Name, Message: err.Error()})
		}
	}

	if len(taskErrors) > 0 {
		s.Stop()
		DrawSummaryTaskErrorTable(taskErrors)
	} else {
		d := color.New(color.FgCyan, color.Bold)
		d.Printf("Hurray!.. Rules has been created on behalf of you")
	}

	return nil

}

func getRuleSet(ruleFlow vo.RuleFlow, rulePath string) (*vo.RuleSet, []*vo.TaskFlow) {
	ruleSet := &vo.RuleSet{}

	rule := &vo.Rule{}

	rule.RuleName = ruleFlow.Metadata.Name
	rule.Purpose = ruleFlow.Spec.Purpose
	rule.Description = ruleFlow.Spec.Description
	rule.AliasRef = ruleFlow.Spec.Aliasref
	rule.Purpose = ruleFlow.Spec.Purpose

	ruleIPValues := make(map[string]interface{}, 0)
	if len(ruleFlow.Spec.Ruleiovalues.Inputs) > 0 {
		for _, inputValue := range ruleFlow.Spec.Ruleiovalues.Inputs {
			ruleIPValues[inputValue.Name] = inputValue.Value
		}
	}

	if rule.RuleIOValues == nil {
		rule.RuleIOValues = &vo.IOValues{}
	}

	rule.RuleIOValues.Inputs = ruleIPValues

	ruleOPValues := make(map[string]interface{}, 0)
	if len(ruleFlow.Spec.Ruleiovalues.Outputs) > 0 {
		for _, outputValue := range ruleFlow.Spec.Ruleiovalues.Outputs {
			ruleOPValues[outputValue.Name] = outputValue.Value
		}
	}

	rule.RuleIOValues.Outputs = ruleOPValues

	taskInfos := make([]interface{}, 0)

	taskFlows := make([]*vo.TaskFlow, 0)

	for _, taskInfo := range ruleFlow.Spec.Tasks {
		if utils.IsNotEmpty(taskInfo.TaskName) {
			taskInfo.TaskName = strcase.ToCamel(taskInfo.TaskName)
		}
		taskFlow := &vo.TaskFlow{}
		if utils.IsNotEmpty(taskInfo.TaskSpec.RulePath) || utils.IsNotEmpty(taskInfo.TaskYamlFilePath) {
			if utils.IsNotEmpty(taskInfo.TaskSpec.RulePath) {
				taskFlow.Kind = "Task"
				taskFlow.Metadata.Name = taskInfo.TaskName
				taskFlow.Spec = taskInfo.TaskSpec
			} else if utils.IsNotEmpty(taskInfo.TaskYamlFilePath) {
				taskFlow, _ = task.GetTaskFlowFromFilePath(taskInfo.TaskYamlFilePath)
			}

			if taskFlow != nil {

				if stringUtils.IsEmpty(taskFlow.Spec.MethodCatalogFilePath) {
					taskFlow.Spec.MethodCatalogFilePath = ruleFlow.Spec.MethodCatalogFilePath
				}

				if utils.IsNotEmpty(taskInfo.TaskName) {
					taskFlow.Metadata.Name = taskInfo.TaskName
				}

				taskFlow.Spec.RulePath = rulePath

				taskFlows = append(taskFlows, taskFlow)
				taskInfos = append(taskInfos, TaskBase{
					Purpose:     taskInfo.TaskName,
					Description: taskInfo.TaskName,
					Type:        "task",
					Aliasref:    taskInfo.TaskAlias,
					TaskGUID:    "{{Task_" + taskInfo.TaskName + "}}",
				})
			}
		}

	}

	rule.TasksInfo = taskInfos

	refMap := make([]*vo.RefStruct, 0)

	for _, ref := range ruleFlow.Spec.Refmaps {
		refArr := strings.Split(strings.ReplaceAll(ref, " ", ""), "=")
		if len(refArr) == 2 {
			targetStr := refArr[0]
			targetArr := strings.Split(targetStr, ".")
			if len(targetArr) == 3 {
				srcStr := refArr[1]
				srcStrArr := strings.Split(srcStr, ".")
				if len(srcStrArr) == 3 {
					refMap = append(refMap, &vo.RefStruct{TargetRef: vo.FieldMap{AliasRef: targetArr[0], FieldType: targetArr[1], VarName: targetArr[2]},
						SourceRef: vo.FieldMap{AliasRef: srcStrArr[0], FieldType: srcStrArr[1], VarName: srcStrArr[2]}})
				}
			}
		}
	}

	rule.RefMaps = refMap

	ruleSet.Rules = []*vo.Rule{rule}

	return ruleSet, taskFlows
}

func DrawSummaryTaskErrorTable(policyCowErrors []*vo.PolicyCowError) {
	table := tablewriter.NewWriter(os.Stdout)

	table.SetHeader([]string{"TaskName", "Error Message"})

	table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor})

	for _, policyCowError := range policyCowErrors {

		row := []string{policyCowError.Name, policyCowError.Message}
		table.Rich(row, []tablewriter.Colors{tablewriter.Colors{}, tablewriter.Colors{tablewriter.Bold, tablewriter.FgRedColor}})
	}

	table.SetCaption(true, "** We have transpiled the code for the tasks. However, the task is not compiling. Please check the source code to fix the errors.")
	table.Render()

}

func CreateSQLRuleWithYAML(yamlFilePath, rulePath string, additionalInfo *vo.AdditionalInfo) error {
	yamlFile, err := os.ReadFile(yamlFilePath)
	if err != nil {
		return err
	}

	var sqlRuleVO vo.SQLRuleVO
	err = yaml.Unmarshal(yamlFile, &sqlRuleVO)
	if err != nil {
		return err
	}

	err = validateSQLRule(&sqlRuleVO)
	if err != nil {
		return err
	}

	taskOutputs := make([]*vo.RefStruct, 0)

	if len(sqlRuleVO.Spec.Outputs.Files) > 0 {
		for i, fileOutput := range sqlRuleVO.Spec.Outputs.Files {

			taskOutputs = append(taskOutputs, &vo.RefStruct{
				SourceRef: vo.FieldMap{FieldType: "Output", VarName: fileOutput.Shortname, AliasRef: "t" + strconv.Itoa(i+1)},
				TargetRef: vo.FieldMap{FieldType: "Output", VarName: fileOutput.Shortname, AliasRef: "*"},
			})

		}
	}

	taskInputVOs := make([]*vo.TaskInputVO, 0)
	taskInputVO := &vo.TaskInputVO{
		TaskName:             sqlRuleVO.Metadata.Name,
		Language:             constants.SupportedLanguagePython.String(),
		RefMaps:              taskOutputs,
		IsSQLRule:            true,
		SupportFilesToCreate: []*vo.SupportedFilesVO{&vo.SupportedFilesVO{FileName: "sqlrule.yaml", FileData: yamlFile}},
	}
	taskInputVOs = append(taskInputVOs, taskInputVO)

	_, err = InitRule(sqlRuleVO.Metadata.Name, rulePath, taskInputVOs, additionalInfo)
	if err != nil {
		return err
	}

	languageSupportedTask := task.GetTask(constants.SupportedLanguagePython)

	directoryPath, err := utils.GetRulePath(rulePath, sqlRuleVO.Metadata.Name)
	if err != nil {
		return errors.New("not a valid path")
	}

	languageSupportedTask.InitTask(sqlRuleVO.Metadata.Name, directoryPath, taskInputVO, additionalInfo)

	err = PrepareRule(directoryPath, "", []string{}, []string{}, true, additionalInfo)
	if err != nil {
		return err
	}

	return nil

}

func validateSQLRule(sqlRuleVO *vo.SQLRuleVO) error {

	if stringUtils.IsEmpty(sqlRuleVO.Metadata.Name) {
		return errors.New("sql rule name cannot be empty")
	}

	if stringUtils.IsEmpty(sqlRuleVO.Spec.Sqldatasource.Sourcetype) {
		return errors.New("source type cannot be empty")
	}

	var sqlDataSource constants.SQLDataSource

	_, err := sqlDataSource.GetSQLDataSource(sqlRuleVO.Spec.Sqldatasource.Sourcetype)
	if err != nil {
		return err
	}
	return nil

}

func ExportRule(filePath string, additionalInfo *vo.AdditionalInfo) (exportedData *vo.ExportedData, err error) {
	directoryPath := ``

	if stringUtils.IsEmpty(additionalInfo.RuleName) && stringUtils.IsEmpty(additionalInfo.RuleGroupName) {
		return nil, errors.New("either rule/rulegroup name should be given")
	}

	if stringUtils.IsEmpty(filePath) {
		if utils.IsNotEmpty(additionalInfo.RuleName) {
			filePath = utils.GetRulePathFromCatalog(additionalInfo, additionalInfo.RuleName)
			if utils.IsEmpty(filePath) {
				filePath = utils.GetCatalogPath(additionalInfo, "", "rules", additionalInfo.RuleName)
			}
			if utils.IsNotValidRulePath(filePath) {
				return nil, errors.New("not a valid rule,check rule folder ")
			}
		} else if utils.IsNotEmpty(additionalInfo.RuleGroupName) {
			filePath = filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.RuleGroupPath, additionalInfo.RuleGroupName)
		} else {
			wd, err := os.Getwd()
			if err != nil {
				return exportedData, err
			}
			filePath = wd
		}

	}
	if utils.IsNotEmpty(filePath) {

		if utils.IsFolderNotExist(filePath) {
			return exportedData, fmt.Errorf("%s not a valid path", filePath)
		}

		if stringUtils.IsNotBlank(filePath) {
			if strings.HasSuffix(filePath, "/") {
				filePath = filePath[:len(filePath)-1]
			}

		}

		directoryPath = filePath

	}

	ruleOutputs := make(map[string]*vo.RuleOutputs)
	ruleNameAndAliasInfo := map[string]string{}

	s := spinner.New(spinner.CharSets[38], 100*time.Millisecond) // Build our new spinner
	s.Prefix = "Preparing to export"
	s.Start()

	rulesCount, err := utils.FetchRuleCountInFolder(directoryPath)
	if err != nil {
		return exportedData, err
	}

	if rulesCount == 0 {
		return exportedData, errors.New("no rules available to download")
	}

	s.Stop()

	bar := fetchProgressBar(rulesCount)

	bar.Describe("Analysing rules...")

	taskExecutions := make(map[string]map[string]map[string]interface{}, 0)

	tempDir := os.TempDir()
	if tempDir == "/tmp" {
		uuid := uuid.New().String()
		tempDir = filepath.Join(tempDir, uuid)

	}
	err = os.MkdirAll(filepath.Join(tempDir, "files"), os.ModePerm)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	previousFolder := path.Dir(path.Dir(filepath.Join(strings.Split(directoryPath, string(os.PathSeparator))...)))
	if strings.HasPrefix(directoryPath, string(os.PathSeparator)) {
		previousFolder = string(os.PathSeparator) + previousFolder
	}

	// if !utils.IsFolderExist(filepath.Join(tempDir, "files")) {
	// 	err := os.MkdirAll(filepath.Join(tempDir, "files"), os.ModePerm)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }

	// if utils.IsFolderExist(filepath.Join(previousFolder, "files")) {

	// 	err := cp.Copy(filepath.Join(previousFolder, "files"), filepath.Join(tempDir, "files"))
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// }

	info, err := os.Stat(directoryPath)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return nil, errors.New("not a valid folder")
	}
	if isRulesDependencyFolder(directoryPath) {
		err = handleDependecyFlow(directoryPath, "Packaging", ruleOutputs, bar, ruleNameAndAliasInfo, false, false, additionalInfo, taskExecutions, tempDir, true, nil)
		if err != nil {
			return nil, err
		}
	} else if isValidRulePath(directoryPath) {
		err := activityHelper(directoryPath, info.Name(), "Packaging", ruleOutputs, &vo.RuleDependency{}, ruleNameAndAliasInfo, bar, false, false, additionalInfo, taskExecutions, tempDir, true, true, nil, nil)
		if err != nil {
			return nil, err
		}

	} else {
		return nil, errors.New("the folder should either rule or rulegroup")
	}

	updateRuleInputFilePath(tempDir, additionalInfo)

	bar.Describe("finished")

	fileName := additionalInfo.RuleName
	tempRuleDir := filepath.Join(tempDir, additionalInfo.RuleName)

	if stringUtils.IsEmpty(fileName) {
		fileName = additionalInfo.RuleGroupName
	}

	if stringUtils.IsEmpty(additionalInfo.DownloadsPath) {
		additionalInfo.DownloadsPath = additionalInfo.PolicyCowConfig.PathConfiguration.DownloadsPath
		if stringUtils.IsEmpty(additionalInfo.DownloadsPath) {
			additionalInfo.DownloadsPath, _ = os.Getwd()
		}
	}
	if !strings.HasPrefix(tempDir, "/tmp") {
		tempDir = tempRuleDir
	}

	if additionalInfo.ExportFileType == "tar" {
		err = utils.TARFiles(tempDir, additionalInfo.DownloadsPath, fileName)
	} else {
		err = utils.ZIPFiles(tempDir, additionalInfo.DownloadsPath, fileName)
	}

	if err != nil {
		return exportedData, err
	}

	exportedData = &vo.ExportedData{FilePath: filepath.Join(additionalInfo.DownloadsPath, fileName)}

	return exportedData, err

}

func PublishRule(filePath string, additionalInfo *vo.AdditionalInfo) error {

	exportedData, err := ExportRule(filePath, additionalInfo)
	if err != nil {
		return err
	}

	compressedFilePath := exportedData.FilePath
	if !strings.HasSuffix(compressedFilePath, "zip") && !strings.HasSuffix(compressedFilePath, "tar") {
		if utils.IsNotEmpty(additionalInfo.ExportFileType) {
			compressedFilePath += "." + additionalInfo.ExportFileType
		} else {
			compressedFilePath += ".tar"
		}
	}

	if utils.IsFileNotExist(compressedFilePath) {
		return errors.New("file not exist")
	}

	defer os.Remove(compressedFilePath)

	headerMap, err := utils.GetAuthHeader(additionalInfo)
	if err != nil {
		return err
	}
	client := resty.New()
	url := fmt.Sprintf("%s/v1/rules", utils.GetCowAPIEndpoint(additionalInfo))

	isOverrideFlow := false
	if additionalInfo.CanOverride && utils.IsNotEmpty(additionalInfo.RuleGUID) {
		isOverrideFlow = true
		url = fmt.Sprintf("%s/v1/rules/%s/update-rule", utils.GetCowAPIEndpoint(additionalInfo), additionalInfo.RuleGUID)
	}

	type result struct {
		ID string `json:"id,omitempty"`
	}

	s := spinner.New(spinner.CharSets[38], 100*time.Millisecond) // Build our new spinner
	s.Prefix = "Publishing ..."
	s.Start()

	resultData := &result{}
	errorData := json.RawMessage{}

	preRequest := client.R().SetHeaders(headerMap)

	metaTagsStr := ``

	if additionalInfo != nil && utils.IsNoneEmpty(additionalInfo.RuleMetaTags) && utils.StringInSlice(constants.RuleMCPTag, additionalInfo.RuleMetaTags) {
		metaTagByts, err := json.Marshal(map[string][]string{
			"Channel":            {"MCP_HOST"},
			constants.RuleMCPTag: {},
		})

		if err == nil && len(metaTagByts) > 0 {
			metaTagsStr = string(metaTagByts)
		}

	}

	request := preRequest.SetFormData(map[string]string{
		"name":        additionalInfo.RulePublisher.Name,
		"type":        "rule",
		"description": additionalInfo.RulePublisher.Description,
		"metaTags":    metaTagsStr,
	}).SetFile("data", compressedFilePath)

	if isOverrideFlow {
		fileByts, err := os.ReadFile(compressedFilePath)
		if err != nil {
			return err
		}

		request = preRequest.SetBody(map[string]any{
			"name":        additionalInfo.RulePublisher.Name,
			"type":        "rule",
			"description": additionalInfo.RulePublisher.Description,
			"fileType":    ".tar",
			"data":        base64.StdEncoding.EncodeToString(fileByts),
			"metaTags":    metaTagsStr,
		})
	}

	resp, err := request.SetResult(resultData).SetError(&errorData).Post(url)

	s.Stop()

	if err != nil {
		return err
	}

	if (!isOverrideFlow && resp.StatusCode() != http.StatusCreated) || (isOverrideFlow && resp.StatusCode() != http.StatusOK) {
		return errors.New("cannot publish the rule")
	}

	if len(errorData) > 4 {
		return errors.New(string(errorData))
	}

	emoji.Println(":megaphone: Rule has been published!!! :party_popper::partying_face::party_popper:")

	rulesCatalogURL := fmt.Sprintf("%s/ui/rules-workflow", utils.GetCowDomain(additionalInfo))

	fmt.Println(utils.ColorLink("You can view the published rule in the rules catalog.", rulesCatalogURL, "italic green"))

	return nil
}

func IsRuleAlreadyPresent(ruleName string, additionalInfo *vo.AdditionalInfo) (bool, error) {
	rules, err := GetAvailableRules(ruleName, additionalInfo)
	if err != nil {
		return false, err
	}

	isRuleAlreadyPresent := len(rules) > 0
	if isRuleAlreadyPresent {
		additionalInfo.RuleGUID = rules[0].ID
	}

	return len(rules) > 0, nil
}

func GetAvailableRules(ruleName string, additionalInfo *vo.AdditionalInfo) ([]*vo.RuleVO, error) {

	collection := &vo.Collection{}
	rules := make([]*vo.RuleVO, 0)
	collection.Items = &rules
	errorData := json.RawMessage{}

	headerMap, err := utils.GetAuthHeader(additionalInfo)
	if err != nil {
		return nil, err
	}
	client := resty.New()

	if utils.IsNotEmpty(ruleName) {
		additionalInfo.RulePublisher.Name = ruleName
	}

	url := fmt.Sprintf("%s/v1/rules", utils.GetCowAPIEndpoint(additionalInfo))

	resp, err := client.R().SetHeaders(headerMap).SetQueryParams(map[string]string{
		"name": additionalInfo.RulePublisher.Name,
	}).SetResult(collection).SetError(&errorData).Get(url)

	if resp.StatusCode() != http.StatusOK {
		return nil, errors.New("cannot fetch the rules")
	}

	return rules, err

}

func writeJsonToFile(filePath string, inputObject *cowvo.ObjectTemplate) error {

	objectByts, err := json.MarshalIndent(inputObject, "", " ")
	if err != nil {
		return err
	}
	err = os.WriteFile(filePath, []byte(objectByts), os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

func UpdateInputFiles(dirPath string, fileInputs *vo.FileInputsVO) error {
	if !utils.IsFolderExist(filepath.Join(dirPath, "files")) {
		if err := os.MkdirAll(filepath.Join(dirPath, "files"), os.ModePerm); err != nil {
			return errors.New("not a valid path")
		}

	}

	if fileInputs.UserObjectAppValue != nil {
		userObjectAppValueFilePath := filepath.Join(dirPath, "files", "UserObjectAppValue.json")
		err := writeJsonToFile(userObjectAppValueFilePath, fileInputs.UserObjectAppValue)
		if err != nil {
			return err
		}
	}
	if fileInputs.UserObjectServerValue != nil {
		userObjectServerValueFilePath := filepath.Join(dirPath, "files", "UserObjectServerValue.json")
		err := writeJsonToFile(userObjectServerValueFilePath, fileInputs.UserObjectServerValue)
		if err != nil {
			return err
		}
	}
	if fileInputs.SystemObjectsValue != nil {
		systemObjectsValueFilePath := filepath.Join(dirPath, "files", "SystemObjectsValue.json")
		if utils.IsFileNotExist(systemObjectsValueFilePath) {
			systemObject, err := json.MarshalIndent(fileInputs.SystemObjectsValue, "", " ")
			if err != nil {
				return err
			}
			err = os.WriteFile(systemObjectsValueFilePath, systemObject, os.ModePerm)
			if err != nil {
				return err
			}

		} else {
			file, err := os.ReadFile(systemObjectsValueFilePath)
			if err != nil {
				return err
			}
			var systemObjects []*cowvo.ObjectTemplate

			err = json.Unmarshal(file, &systemObjects)
			if err != nil {
				return err
			}

			if len(systemObjects) > 0 {
				for idx1, sysobject := range systemObjects {
					for idx2, sysObjectValue := range fileInputs.SystemObjectsValue {
						if sysobject.App.ApplicationName == sysObjectValue.App.ApplicationName {
							systemObjects[idx1] = fileInputs.SystemObjectsValue[idx2]
						}
					}
				}
			}
			sysObjects, err := json.MarshalIndent(systemObjects, "", " ")
			if err != nil {
				return err
			}
			err = os.WriteFile(systemObjectsValueFilePath, sysObjects, os.ModePerm)
			if err != nil {
				return err
			}
		}
	}
	if fileInputs.TaskInputValue != nil {
		taskInputValuePath := filepath.Join(dirPath, "files", "TaskInputValue.json")
		objectByts, err := json.MarshalIndent(fileInputs.TaskInputValue, "", " ")
		if err == nil {
			err = os.WriteFile(taskInputValuePath, objectByts, os.ModePerm)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

type TaskBase struct {
	Purpose     string
	Description string
	Type        string `json:"type,omitempty"`
	Aliasref    string `json:"aliasref,omitempty"`
	TaskGUID    string `json:"taskguid,omitempty"`
}

func CreateRuleWithYAMLV2(ruleYAML *vo.RuleYAMLVO, additionalInfo *vo.AdditionalInfo) *vo.ErrorResponseVO {

	if additionalInfo == nil {
		addInfo, err := utils.GetAdditionalInfoFromEnv()
		if err != nil {
			return &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
				Message: "Essential/basic information is missing", Description: "Essential/basic information is missing.",
				ErrorDetails: utils.GetValidationError(err)}}
		}

		additionalInfo = addInfo
	}
	fmt.Println("additionalInfo::", additionalInfo)

	ruleAddInfo, errorVO := utils.GetTaskInfosFromRule(ruleYAML, additionalInfo)
	fmt.Println("ruleAddInfo: ", ruleAddInfo)
	if errorVO != nil {
		return &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: errorVO}
	}

	rulesPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath, "rules")
	if additionalInfo.GlobalCatalog {
		rulesPath = additionalInfo.PolicyCowConfig.PathConfiguration.RulesPath
	}

	fmt.Println("rulesPath ::", rulesPath)
	if len(ruleYAML.Spec.Tasks) > 0 {
		availableTasks := utils.GetTasks(additionalInfo)
		availableTaskNames := make(map[string]struct{}, len(availableTasks))
		for _, task := range availableTasks {
			availableTaskNames[task.Name] = struct{}{}
		}
		unAvailableTasks := make([]string, 0)
		for _, task := range ruleYAML.Spec.Tasks {
			if _, ok := availableTaskNames[task.Name]; !ok {
				unAvailableTasks = append(unAvailableTasks, task.Name)
			}
		}
		if len(unAvailableTasks) > 0 {
			return &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
				Message: "Task(s) not found", Description: fmt.Sprintf("Some tasks cannot be found in the catalogs :%s", strings.Join(unAvailableTasks, ","))}}
		}
	}

	if len(ruleYAML.Spec.UserInputs) > 0 {

		// userInputs := make(map[string]interface{}, 0)

		unAvailableInputs := make([]string, 0)

		for _, userInput := range ruleYAML.Spec.UserInputs {

			if ruleAddInfo.RuleIOMapInfo != nil && slices.Contains(ruleAddInfo.RuleIOMapInfo.InputVaribales, userInput.Name) {

				// if userInput.Type == constants.DeclarativesDataTypeFILE {
				// 	folderPath := fmt.Sprintf("%s/%s", ruleYAML.Meta.Name, userInput.Name)

				// 	fileName := userInput.Name
				// 	if utils.IsNotEmpty(userInput.Format) {
				// 		fileName += "." + userInput.Format
				// 	}
				// 	fileBytesAsStr, ok := userInput.Value.(string)
				// 	if !ok {
				// 		return &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
				// 			Message: "not a valid file data", Description: fmt.Sprintf("File content is invalid for '%s'", userInput.Name)}}
				// 	}
				// 	minioFileVO := &vo.MinioFileVO{FileName: fileName, Path: folderPath, BucketName: constants.BucketNameRuleInputs, FileContent: []byte(fileBytesAsStr)}
				// 	minioUploadResp, err := UploadFileToMinio(minioFileVO)
				// 	if err != nil {
				// 		return &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
				// 			Message: "minio upload failed", Description: fmt.Sprintf("Cannot upload file into minio for varaible '%s'", userInput.Name),
				// 			ErrorDetails: utils.GetValidationError(err)}}
				// 	}

				// 	fmt.Println("minioUploadResp.FileURL :", minioUploadResp.FileURL)

				// 	userInputs[userInput.Name] = minioUploadResp.FileURL
				// } else {
				// 	userInputs[userInput.Name] = userInput.Value
				// }
			} else {
				unAvailableInputs = append(unAvailableInputs, userInput.Name)
			}

		}

		if len(unAvailableInputs) > 0 {
			return &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
				Message: "Invalid input variable", Description: fmt.Sprintf("Found these rule input variable(s) that are not mapped to any of the tasks: %s", strings.Join(unAvailableInputs, ","))}}
		}

		userInputs, errorVO := RuleInputsToMap(ruleYAML.Meta.Name, ruleYAML.Spec.UserInputs)
		if errorVO != nil {
			return &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: errorVO}
		}

		ruleYAML.Spec.Input = userInputs

	}

	additionalInfo.RuleYAMLVO = ruleYAML

	rulePath, err := InitRule(ruleYAML.Meta.Name, rulesPath, ruleAddInfo.TaskInfos, additionalInfo)

	fmt.Println("rulePath :", rulePath)

	if err != nil {
		return &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "Cannot create rule", Description: "Cannot create rule",
			ErrorDetails: utils.GetValidationError(err)}}
	}

	fmt.Println("ruleYAML.Spec.UserInputs :", ruleYAML.Spec.UserInputs)

	return nil
}

func DownloadFileFromMinio(absoluteFilePath string) (*vo.MinioFileVO, error) {

	fileURL, err := url.Parse(absoluteFilePath)
	if err != nil {
		return nil, fmt.Errorf("invalid file URL: %w", err)
	}
	// Default bucketName
	bucketName := "demo"
	if fileURL.Scheme == "http" {
		splitPath := strings.Split(fileURL.Path, "/")
		if len(splitPath) > 2 {
			bucketName = splitPath[1]
		}
	}

	minoEndpoint := utils.Getenv(constants.EnvMinioLoginURL, "cowstorage:9000")
	// Supress log
	log.SetOutput(io.Discard)

	minioClient, err := cowStorage.RegisterMinio(minoEndpoint, utils.Getenv(constants.EnvMinioRootUser, ""), utils.Getenv(constants.EnvMinioRootPassword, ""), bucketName)

	if err != nil {
		return nil, err
	}

	if minioClient == nil {
		return nil, errors.New("cannot create minio client")
	}

	objectPath := strings.TrimPrefix(fileURL.Path, fmt.Sprintf("/%v", bucketName))
	bucketName, prefix := cowStorage.GetBucketAndPrefix(bucketName)
	objectPath = prefix + objectPath

	if cowStorage.IsAmazonS3Host(absoluteFilePath) {
		parts := strings.Split(fileURL.Path, "/")
		if len(parts) < 4 {
			return nil, errors.New("invalid URL structure, cannot extract bucket and object")
		}
		bucketName = parts[3]
		objectPath = strings.Join(parts[4:], "/")

		if prefix := fileURL.Query().Get("prefix"); prefix != "" {
			objectPath = prefix
		}
	}

	object, err := minioClient.GetObject(context.Background(), bucketName, objectPath, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer object.Close()
	fileContent, err := io.ReadAll(object)
	if err != nil {
		return nil, err
	}

	return &vo.MinioFileVO{FileContent: fileContent, FileName: filepath.Base(absoluteFilePath)}, nil

}

func ValidateApplication(applicationValidatorVO *vo.ApplicationValidatorVO, ruleName string, additionalInfo *vo.AdditionalInfo) (*vo.ApplicationValidatorRespVO, *vo.ErrorResponseVO) {

	if additionalInfo == nil {
		addInfo, err := utils.GetAdditionalInfoFromEnv()
		if err != nil {
			return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
				Message: "Essential/basic information is missing", Description: "Essential/basic information is missing.",
				ErrorDetails: utils.GetValidationError(err)}}
		}

		additionalInfo = addInfo
	}
	languages, err := utils.GetApplicationLanguageFromRule(ruleName, additionalInfo)
	if err != nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "Failed to get ApplicationType language", Description: fmt.Sprintf("The language for the %s ApplicationType could not be retrieved ", applicationValidatorVO.ApplicationType)}}
	}

	var language string
	rulePath := utils.GetRulePathFromCatalog(additionalInfo, ruleName)
	ruleYaml := &vo.RuleYAMLVO{}
	ruleFile, err := os.ReadFile(filepath.Join(rulePath, constants.RuleYamlFile))
	if err != nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "Failed to read rule.yaml file", Description: fmt.Sprintf("The language for the %s ApplicationType could not be retrieved ", applicationValidatorVO.ApplicationType)}}
	}
	err = yaml.Unmarshal(ruleFile, &ruleYaml)
	if err != nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "Failed to unmarshal rule.yaml file", Description: fmt.Sprintf("The language for the %s ApplicationType could be retrieved from the rule details ", applicationValidatorVO.ApplicationType)}}
	}

	for _, task := range ruleYaml.Spec.Tasks {
		if task.AppTags != nil {
			if reflect.DeepEqual(task.AppTags, applicationValidatorVO.AppTags) {
				if taskLanguage, exists := languages[task.Name]; exists {
					language = taskLanguage
					break
				}
			}
		}
		if utils.IsEmpty(language) {
			language = languages[task.Name]
		}
	}

	appClassPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationTypeConfigPath, fmt.Sprintf("%s.yaml", applicationValidatorVO.ApplicationType))
	fmt.Println("appClassPath :", appClassPath)

	if utils.IsFileNotExist(appClassPath) {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "Invalid App", Description: fmt.Sprintf("not able to find '%s' ApplicationType", applicationValidatorVO.ApplicationType)}}
	}

	applicationInfo, err := utils.GetApplicationWithCredential(appClassPath, additionalInfo.PolicyCowConfig.PathConfiguration.CredentialTypeConfigPath)
	if err != nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "Invalid App", Description: fmt.Sprintf("not able to find '%s' ApplicationType", applicationValidatorVO.ApplicationType),
			ErrorDetails: utils.GetValidationError(err)}}
	}

	baseFolder := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationTypesPath, language)

	if constants.SupportedLanguagePython.String() == language {
		baseFolder = filepath.Join(baseFolder, constants.ApplicationTypes)
	}

	appName := strings.ToLower(applicationValidatorVO.ApplicationType)

	applicationPath := filepath.Join(baseFolder, appName)

	if utils.IsFolderNotExist(applicationPath) {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "Invalid ApplicationType", Description: fmt.Sprintf("Cannot find the ApplicationType '%s'", applicationValidatorVO.ApplicationType)}}
	}

	validateApplicationTask := filepath.Join(applicationPath, fmt.Sprintf("Validate%s", applicationValidatorVO.ApplicationType))

	if utils.IsFolderNotExist(validateApplicationTask) {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "Validation task missing", Description: fmt.Sprintf("Cannot find the validation task for '%s'", applicationValidatorVO.ApplicationType)}}
	}

	inputYAMLPath := filepath.Join(validateApplicationTask, constants.TaskInputYAMLFile)

	taskInput := vo.TaskInputV2{}

	if utils.IsFileExist(inputYAMLPath) {
		inputByts, err := os.ReadFile(inputYAMLPath)
		if err != nil {
			fmt.Printf("Error while reading yaml file: %s", err)
		}

		fmt.Println("inputByts   :::", string(inputByts))

		err = yaml.Unmarshal(inputByts, &taskInput)
		if err != nil {
			fmt.Printf("Error in unmarshalling task input yaml,error: %s", err)
		}

		defer func(inputByts []byte) {
			os.WriteFile(inputYAMLPath, inputByts, os.ModePerm)
		}(inputByts)

	} else {
		taskYaml := constants.TaskInputYAML
		err = yaml.Unmarshal([]byte(taskYaml), &taskInput)
		if err != nil {
			fmt.Printf("Error in unmarshalling task input yaml,error: %s", err)
		}
	}

	appAbstract := &vo.AppAbstract{}
	appAbstract.ApplicationName = applicationInfo.App.Meta.Name
	appAbstract.ApplicationURL = applicationInfo.App.Spec.URL
	appAbstract.ApplicationPort = strconv.Itoa(applicationInfo.App.Spec.Port)

	credentials := utils.GetCredentialYAMLObjectV2(applicationInfo.Credential)
	foundCredential := false

	for _, mapItem := range credentials.UserDefinedCredentials {
		if credName, ok := mapItem.Key.(string); ok && credName == applicationValidatorVO.CredentialType {
			foundCredential = true
			break
		}
	}

	if !foundCredential {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "Invalid CredentialType", Description: fmt.Sprintf("The ApplicationType doesn't support credention '%s'", applicationValidatorVO.CredentialType)}}
	}

	userDefinedCredentials := map[string]interface{}{}

	// INFO : If credential value is empty, then we don't consider the credentialType (i.e) it goes with empty userDefinedCredentials

	if len(applicationValidatorVO.CredentialValues) > 0 {
		userDefinedCredentials[applicationValidatorVO.CredentialType] = applicationValidatorVO.CredentialValues
	}

	appAbstract.UserDefinedCredentials = userDefinedCredentials

	_, err = url.ParseRequestURI(applicationValidatorVO.ApplicationURL)
	if err != nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "Invalid URL", Description: "The applicationURL is not valid"}}
	}

	appAbstract.ApplicationURL = applicationValidatorVO.ApplicationURL
	appAbstractByts, err := json.Marshal(appAbstract)
	if err == nil {
		json.Unmarshal(appAbstractByts, &taskInput.UserInputs)
	}

	taskInput.FromDate_ = "{{FROM_DATE}}"
	taskInput.ToDate_ = "{{FROM_DATE}}"

	taskInputByts, err := yaml.Marshal(taskInput)
	if err != nil {
		fmt.Printf("Error in marshalling task, error : %s", err)
	}

	dateValue := strings.ReplaceAll(string(taskInputByts), "'{{FROM_DATE}}'", time.Now().Format("2006-01-02"))
	dateValue = strings.ReplaceAll(dateValue, "\"{{FROM_DATE}}\"", time.Now().Format("2006-01-02"))
	dateValue = strings.ReplaceAll(dateValue, "{{FROM_DATE}}", time.Now().Format("2006-01-02"))

	fmt.Println("dateValue :", dateValue)

	err = os.WriteFile(inputYAMLPath, []byte(dateValue), os.ModePerm)
	if err != nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "VALIDATION_FAILED", Description: "Error while handling the input data",
			ErrorDetails: utils.GetValidationError(err)}}
	}

	defer func() {
		os.Remove(filepath.Join(validateApplicationTask, constants.FileNameTaskInput))
		os.Remove(filepath.Join(validateApplicationTask, constants.FileNameTaskOutput))
		os.RemoveAll(filepath.Join(validateApplicationTask, filepath.Base(baseFolder)))
	}()

	var cmd *exec.Cmd
	if constants.SupportedLanguagePython.String() == language {

		tmpDir := os.TempDir()
		tmpAppConnectionDir := filepath.Join(tmpDir, constants.ApplicationTypes)
		err := cp.Copy(baseFolder, tmpAppConnectionDir)
		if err != nil {
			fmt.Println("Error copying applicationtypes to temporary directory:", err)
		}

		err = cp.Copy(tmpAppConnectionDir, filepath.Join(validateApplicationTask, filepath.Base(baseFolder)))
		if err != nil {
			fmt.Println("Error copying files to validateApplicationTask:", err)
		}
		if requirementsFilePath := filepath.Join(filepath.Dir(baseFolder), "requirements.txt"); utils.IsFileExist(requirementsFilePath) {
			cmd := exec.Command("python3", "-m", "pip", "install", "-r", "requirements.txt")
			cmd.Dir = filepath.Dir(baseFolder)
			_, err := cmd.Output()
			if err != nil {
				return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
					Message: "VALIDATION_FAILED", Description: "Error while installing appconnection packages",
					ErrorDetails: utils.GetValidationError(err)}}
			}
		}

		if requirementsFilePath := filepath.Join(validateApplicationTask, "requirements.txt"); utils.IsFileExist(requirementsFilePath) {
			cmd := exec.Command("python3", "-m", "pip", "install", "-r", "requirements.txt")
			cmd.Dir = validateApplicationTask
			_, err := cmd.Output()
			if err != nil {
				return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
					Message: "VALIDATION_FAILED", Description: "Error while installing validation task packages",
					ErrorDetails: utils.GetValidationError(err)}}
			}
		}

		cmd = exec.Command("python3", "-u", "autogenerated_main.py")

	} else {
		cmd = exec.Command("bash", "-c", "go mod tidy && go run *.go")
	}

	cmd.Dir = validateApplicationTask

	_, err = cmd.CombinedOutput()

	if err != nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "VALIDATION_FAILED", Description: "Task validation failed. Please contact the developer",
			ErrorDetails: utils.GetValidationError(err)}}
	}

	outputBytes, err := os.ReadFile(filepath.Join(validateApplicationTask, constants.FileNameTaskOutput))

	if err != nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "VALIDATION_FAILED", Description: "Cannot capture the validation status from validation task. output file is missing from the task."}}
	}

	respVO := &vo.ApplicationValidatorRespVO{Valid: false}

	outputMap := make(map[string]interface{}, 0)

	json.Unmarshal(outputBytes, &outputMap)

	if value, ok := outputMap["Outputs"]; ok {
		if valueMap, ok := value.(map[string]interface{}); ok {
			if isValidated, ok := valueMap["IsValidated"]; ok {
				if isValidated, ok := isValidated.(bool); ok {
					respVO.Valid = isValidated
				}
			}
			if validationMessage, ok := valueMap["ValidationMessage"]; ok {
				if validationMessage, ok := validationMessage.(string); ok {
					respVO.Message = validationMessage
				}
			}
		}
	}

	if errStr, ok := outputMap["errors"]; ok {
		errorStr, _ := errStr.(string)
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "VALIDATION_FAILED", Description: errorStr}}
	}

	if errStr, ok := outputMap["error"]; ok {
		errorStr, _ := errStr.(string)
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "VALIDATION_FAILED", Description: errorStr}}
	}

	fmt.Println("outputBytes :", string(outputBytes))

	return respVO, nil
}

func ExecuteRuleV2(executeRuleVO *vo.RuleExecutionVO, additionalInfo *vo.AdditionalInfo) (*vo.RuleProgressVO, *vo.ErrorResponseVO) {

	if additionalInfo == nil {
		addInfo, err := utils.GetAdditionalInfoFromEnv()
		if err != nil {
			return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
				Message: "Essential/basic information is missing", Description: "Essential/basic information is missing.",
				ErrorDetails: utils.GetValidationError(err)}}
		}

		additionalInfo = addInfo
	}

	rulesPath := utils.GetRulePathFromCatalog(additionalInfo, executeRuleVO.RuleName)

	if utils.IsNotValidRulePath(rulesPath) {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "Invalid rule", Description: "Cannot find the rule",
			ErrorDetails: utils.GetValidationError(fmt.Errorf("not a valid path. %s ", rulesPath))}}
	}
	additionalInfo.RuleName = executeRuleVO.RuleName
	additionalInfo.RuleExecutionVO = executeRuleVO
	additionalInfo.PreserveRuleExecutionSetUp = true

	err := ExecuteRule(rulesPath, "", make([]string, 0), []string{""}, false, additionalInfo)
	if err != nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "Execution failed", Description: "Rule execution has been failed",
			ErrorDetails: utils.GetValidationError(err)}}
	}

	return nil, nil
}

func ValidateRuleForExecution(executeRuleVO *vo.RuleExecutionVO, additionalInfo *vo.AdditionalInfo) *vo.ErrorResponseVO {
	if additionalInfo == nil {
		addInfo, err := utils.GetAdditionalInfoFromEnv()
		if err != nil {
			return &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
				Message: "Essential/basic information is missing", Description: "Essential/basic information is missing.",
				ErrorDetails: utils.GetValidationError(err)}}
		}

		additionalInfo = addInfo
	}

	rulesPath := utils.GetRulePathFromCatalog(additionalInfo, executeRuleVO.RuleName)

	if utils.IsEmpty(rulesPath) || utils.IsNotValidRulePath(rulesPath) {
		return &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "Invalid rule", Description: "Cannot find the rule",
			ErrorDetails: utils.GetValidationError(fmt.Errorf("not a valid path. %s ", rulesPath))}}
	}

	return nil
}

func getFileBytesFromInterface(value interface{}) ([]byte, error) {
	switch v := value.(type) {
	case []byte:
		return v, nil
	default:
		fileBytesAsStr, ok := value.(string)
		if !ok {

			return nil, errors.New("not a valid file data")
		}

		fileBytes, err := base64.StdEncoding.DecodeString(fileBytesAsStr)
		if err != nil {
			return nil, errors.New("not a valid file data")
		}
		return fileBytes, nil
	}
}

func RuleInputsToMap(ruleName string, ruleInputs []*vo.RuleUserInputVO) (map[string]interface{}, *vo.ErrorVO) {
	userInputs := make(map[string]interface{}, 0)

	for _, userInput := range ruleInputs {

		if userInput.DataType == constants.DeclarativesDataTypeFILE || userInput.DataType == constants.DeclarativesDataTypeHTTP_CONFIG {
			if strValue, ok := userInput.DefaultValue.(string); ok && utils.IsNotEmpty(strValue) {
				if strings.HasPrefix(strValue, "http://") || strings.HasPrefix(strValue, "https://") {
					userInputs[userInput.Name] = strValue
				} else {
					folderPath := fmt.Sprintf("%s/%s", ruleName, userInput.Name)

					fileName := userInput.Name
					if utils.IsNotEmpty(userInput.Format) {
						fileName += "." + userInput.Format
					}

					fileBytes, err := getFileBytesFromInterface(userInput.DefaultValue)
					if err != nil {
						return nil, &vo.ErrorVO{
							Message: "not a valid file data", Description: fmt.Sprintf("File content is invalid for '%s'", userInput.Name)}
					}

					minioFileVO := &vo.MinioFileVO{FileName: fileName, Path: folderPath, BucketName: constants.BucketNameRuleInputs, FileContent: fileBytes}
					minioUploadResp, errResp := storage.UploadFileToMinio(minioFileVO, nil)
					if errResp != nil {
						return nil, errResp.Error
					}

					userInputs[userInput.Name] = minioUploadResp.FileURL
				}
			}

		} else {
			userInputs[userInput.Name] = userInput.DefaultValue
		}

	}

	return userInputs, nil
}

func GetAvailableLanguages(applicationVO *vo.ApplicationVO, additionalInfo *vo.AdditionalInfo) ([]string, error) {
	if additionalInfo == nil {
		additionalInfo, _ = utils.GetAdditionalInfoFromEnv()
	}
	availableLanguages := []string{}
	packageName := strings.ToLower(applicationVO.Name)
	appDeclarativesPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.DeclarativePath, constants.UserDefinedApplicationPath)

	appDeclarativesPath = filepath.Join(appDeclarativesPath, strings.ToLower(applicationVO.Name))
	if utils.IsFolderNotExist(appDeclarativesPath) {
		return nil, fmt.Errorf("ApplicationType not available")
	}
	appPath := additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationTypesPath
	if utils.IsFolderExist(filepath.Join(appPath, "go", packageName)) {
		availableLanguages = append(availableLanguages, "go")
	}
	if utils.IsFolderExist(filepath.Join(appPath, "python", "applicationtypes", packageName)) {
		availableLanguages = append(availableLanguages, "python")
	}
	return availableLanguages, nil

}

func updateRuleInputFilePath(tempDir string, additionalInfo *vo.AdditionalInfo) {
	tmpRuleDir := filepath.Join(tempDir, additionalInfo.RuleName)
	ruleJSONPath := filepath.Join(tmpRuleDir, constants.RuleFile)
	fileData, _ := os.ReadFile(ruleJSONPath)
	var ruleSet vo.RuleSet
	if err := json.Unmarshal(fileData, &ruleSet); err != nil {
		log.Printf("Error unmarshalling rule JSON data: %v", err)
		return
	}

	for _, inputMeta := range ruleSet.Rules[0].RuleIOValues.InputsMeta__ {
		if inputMeta.DataType == constants.InputMetaFileType || inputMeta.DataType == constants.DeclarativesDataTypeHTTP_CONFIG {
			inputMeta.DefaultValue = constants.MinioFilePath
			ruleSet.Rules[0].RuleIOValues.Inputs[inputMeta.Name] = constants.MinioFilePath
		}
		if inputMeta.DataType == constants.DeclarativesDataTypeHTTP_CONFIG {
			inputMeta.DataType = constants.DeclarativesDataTypeFILE
		}
	}

	for key, value := range ruleSet.Rules[0].RuleIOValues.Inputs {
		if inputValue, ok := value.(string); ok {
			if strings.HasPrefix(inputValue, "http://localhost") || strings.HasPrefix(inputValue, "http://cowstorage") || strings.HasPrefix(inputValue, "http://127.0.0.1:9000/") || strings.HasPrefix(inputValue, "file://") {
				ruleSet.Rules[0].RuleIOValues.Inputs[key] = constants.MinioFilePath
			}
		}
	}
	updatedFileData, err := json.Marshal(ruleSet)
	if err != nil {
		log.Printf("Error marshalling updated rule JSON data: %v", err)
		return
	}
	err = os.WriteFile(ruleJSONPath, updatedFileData, 0644)
	if err != nil {
		log.Printf("Error writing updated rule JSON file: %v", err)
		return
	}

}

func updateLinkedApplicationCredentials(appList map[string][]*vo.AppAbstract, linkedApps []*vo.LinkedAppsCredentials) {
	for _, linkedApp := range linkedApps {
		var appAbstract *vo.AppAbstract
		for _, app := range appList[linkedApp.ApplicationName] {
			if app.ApplicationName == linkedApp.ApplicationName {
				appAbstract = app
				break
			}
		}
		if appAbstract != nil {
			if utils.IsNotEmpty(linkedApp.ApplicationURL) {
				appAbstract.ApplicationURL = linkedApp.ApplicationURL
			}
			if utils.IsNotEmpty(linkedApp.CredentialType) && len(linkedApp.CredentialValues) > 0 {
				appAbstract.UserDefinedCredentials = map[string]interface{}{
					linkedApp.CredentialType: linkedApp.CredentialValues,
				}
			}
			if len(linkedApp.LinkedApplications) > 0 {
				updateLinkedApplicationCredentials(appAbstract.LinkedApplications, linkedApp.LinkedApplications)
			}
		}
	}
}

func FetchAppCredentials(applicationID string, additionalInfo *vo.AdditionalInfo) (map[string]interface{}, error) {
	headerMap, err := utils.GetAuthHeader(additionalInfo)
	if err != nil {
		return nil, fmt.Errorf("error getting auth header: %v", err)
	}

	client := resty.New()
	url := fmt.Sprintf("%s/v1/configuration/fetch-application", constants.CoWConfigurationServiceURL)
	body := map[string]interface{}{
		"applicationId":     applicationID,
		"includeCredential": true,
	}

	response, err := client.R().SetHeaders(headerMap).SetBody(body).Post(url)
	if err != nil {
		return nil, fmt.Errorf("error while making the request to the url %s: %v", url, err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(response.Body(), &result); err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %v", err)
	}
	return result, nil
}

func InstallPythonDependenciesWithRequirementsTxtFile(srcDir string) {
	reqPath := filepath.Join(srcDir, "requirements.txt")
	if _, err := os.Stat(reqPath); err == nil {
		content, _ := os.ReadFile(reqPath)
		var installList []string
		for _, pkg := range strings.Split(string(content), "\n") {
			pkg = strings.TrimSpace(pkg)
			if utils.IsEmpty(pkg) || strings.HasPrefix(pkg, "#") {
				continue
			}

			if idx := strings.Index(pkg, "#"); idx != -1 {
				pkg = strings.TrimSpace(pkg[:idx])
			}

			if _, loaded := pythonPackages.LoadOrStore(pkg, true); !loaded {
				installList = append(installList, pkg)
			}
		}

		if !utils.IsNoneEmpty(installList) {
			return
		}
		cmd := exec.Command("python3", "-m", "pip", "install")
		cmd.Args = append(cmd.Args, installList...)
		cmd.Dir = srcDir
		cmdByts, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Println("installation error :", err)
		} else {
			fmt.Println("installation output :", string(cmdByts))
		}
	}
}
