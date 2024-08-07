package executions

import (
	"bufio"
	"bytes"
	"cowlibrary/constants"
	"cowlibrary/utils"
	"cowlibrary/vo"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type RuleExecutions struct {
}

func (ruleExecutions *RuleExecutions) Create(cowRuleExecutions *vo.CowRuleExecutions,
	additionalInfo *vo.AdditionalInfo, executionPath string) error {

	if utils.IsEmpty(executionPath) {
		executionPath = additionalInfo.PolicyCowConfig.PathConfiguration.ExecutionPath
	}

	cowRuleExecutions.CreatedAt = time.Now()

	if len(cowRuleExecutions.RuleOutputs) > 0 && utils.IsNotEmpty(cowRuleExecutions.RuleOutputs[0].RuleGroup) {
		cowRuleExecutions.RuleGroupName = cowRuleExecutions.RuleOutputs[0].RuleGroup
	}

	executionsPath := filepath.Join(executionPath, constants.ExecutionsFile)

	if !utils.IsFileExist(executionsPath) {
		if err := os.MkdirAll(executionPath, os.ModePerm); err != nil {
			return err
		}
	}

	file, err := os.OpenFile(executionsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		fmt.Printf("could not open %s", constants.ExecutionsFile)
		return err
	}

	defer file.Close()

	if cowRuleExecutions != nil {

		substring := `"executionID"` + ":" + `"` + cowRuleExecutions.ExecutionID + `",`
		var linetoreplace string
		execfile, _ := os.Open(executionsPath)
		scanner := bufio.NewScanner(execfile)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, substring) {
				linetoreplace = line
				break
			}
		}
		byts, err := json.Marshal(cowRuleExecutions)
		if err != nil {
			return err
		}
		if utils.IsNotEmpty(linetoreplace) {
			bytefile, err := os.ReadFile(executionsPath)
			if err != nil {
				return err
			}
			output := bytes.Replace(bytefile, []byte(linetoreplace), byts, -1)
			if err = os.WriteFile(executionsPath, output, 0666); err != nil {
				return err
			}
		} else {
			_, err = file.Write(byts)
			if err != nil {
				return err
			}

			if _, err = file.WriteString("\n"); err != nil {
				return err
			}
		}

	}
	return nil

}
