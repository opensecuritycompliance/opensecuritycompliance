package main

import (
	jumphost "appconnections/kubernetes"
	cowStorage "appconnections/minio"
	cowlibutils "cowlibrary/utils"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (inst *TaskInstance) EvaluateCISBenchmarkForKubernetes(inputs *UserInputs, outputs *Outputs) (err error) {

	errorDetails := []ErrorVO{}

	defer func() {
		if len(errorDetails) > 0 {
			outputs.LogFile, err = inst.uploadLogFile(errorDetails)
		}
	}()

	output := make([]*KubebenchResult, 0)

	jumphostObj := jumphost.Kubernetes{UserDefinedCredentials: &inst.SystemInputs.UserObject.App.UserDefinedCredentials, AppURL: inst.SystemInputs.UserObject.App.ApplicationURL}

	ruleConfigVO, err := inst.getConfigDataFromInputs(inputs)
	if err != nil {
		errorDetails = append(errorDetails, ErrorVO{Error: err.Error()})
		return nil
	}

	cmdOutput, cmdErr := inst.runKubernetesCommandForJumpHost(jumphostObj)
	if len(cmdErr) > 0 {
		errorDetails = cmdErr
		return nil
	}

	organisedCmdOutput := processCmdOutputData(cmdOutput)
	if cowlibutils.IsEmpty(inputs.ControlNumber) || inputs.ControlNumber == "*" {
		output = mapToStruct(organisedCmdOutput)
	} else {
		if _, ok := organisedCmdOutput[inputs.ControlNumber]; !ok {

			errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("Control number '%v' is not exist.", inputs.ControlNumber)})
			return nil
		} else {
			output = append(output, organisedCmdOutput[inputs.ControlNumber]...)
		}
	}

	output, evidenceName := inst.ProcessOpToStandardCcStruct(output, ruleConfigVO)

	outputs.CISBenchmarkForKubernetesFile, err = inst.uploadOutputFile(output, evidenceName)
	if err != nil {
		errorDetails = append(errorDetails, ErrorVO{Error: err.Error()})
		return nil
	}

	return nil
}

func (inst *TaskInstance) getConfigDataFromInputs(inputs *UserInputs) ([]RuleConfigVO, error) {

	var ruleConfigVO []RuleConfigVO

	err := inst.validateInputConfigFile(inputs)
	if err != nil {
		return nil, err
	}

	ruleConfigBytes, err := cowStorage.DownloadFile(inputs.RuleConfig, inst.SystemInputs)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(ruleConfigBytes, &ruleConfigVO)
	if err != nil {
		return nil, fmt.Errorf("Error while unmarshalling rule config file: %v", err)
	}
	return ruleConfigVO, nil
}
func (inst *TaskInstance) validateInputConfigFile(inputs *UserInputs) error {

	if cowlibutils.IsEmpty(inputs.RuleConfig) || inputs.RuleConfig == "<<MINIO_FILE_PATH>>" {
		return errors.New("The input Config file is missing. Please upload a valid Config file")
	}

	fileExtension := filepath.Ext(inputs.RuleConfig)
	if fileExtension != ".json" {
		return fmt.Errorf("The provided file type is not supported. Please upload a file with the .json extension. The uploaded file is of an unsupported type (%s)", fileExtension)
	}
	return nil
}

func (inst *TaskInstance) ProcessOpToStandardCcStruct(output []*KubebenchResult, ruleConfigVO []RuleConfigVO) ([]*KubebenchResult, string) {

	result := []*KubebenchResult{}

	evidenceName := ""
	for _, kubebenchResult := range output {

		for _, ruleConfig := range ruleConfigVO {
			if ruleConfig.ControlNumber == kubebenchResult.ControlNumber {

				evidenceName = ruleConfig.EvidenceName
				kubebenchResult.ControlDescription = ruleConfig.ControlDescription
				kubebenchResult.ParentControlDescription = ruleConfig.ParentControlInfo
				if kubebenchResult.ComplianceStatus == "COMPLIANT" {
					kubebenchResult.ValidationStatusCode = ruleConfig.Compliant.ValidationStatusCode
					kubebenchResult.ValidationStatusNotes = ruleConfig.Compliant.ValidationStatusNotes
					kubebenchResult.ComplianceStatusReason = ruleConfig.Compliant.ComplianceStatusReason
				} else {
					kubebenchResult.ValidationStatusCode = ruleConfig.NonCompliant.ValidationStatusCode
					kubebenchResult.ValidationStatusNotes = ruleConfig.NonCompliant.ValidationStatusNotes
					kubebenchResult.ComplianceStatusReason = ruleConfig.NonCompliant.ComplianceStatusReason
					if kubebenchResult.RemediationSteps == "" {
						kubebenchResult.RemediationSteps = ruleConfig.NonCompliant.Remediation
					}
				}

			}

		}
		result = append(result, kubebenchResult)

	}

	if len(result) > 1 {
		evidenceName = "CISBenchmarkForKubernetesResults"
	}

	return result, evidenceName
}

func (inst *TaskInstance) runKubernetesCommandForJumpHost(jumphostObj jumphost.Kubernetes) (map[string]*KubebenchResult, []ErrorVO) {

	errorDetails := []ErrorVO{}
	var output map[string]*KubebenchResult
	cmd := "kubectl config view -o jsonpath=" + "'{\"Cluster\\tContexts\\n\"}{range .contexts[*]}{.context.cluster}{\"\\t\"}{.name}{\"\\n\"}{end}'"
	contextDetails, err := jumphostObj.RunUnixCommands(cmd)
	if err != nil {
		errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("Error while running get config view cmd: '%v'.", contextDetails)})
		return nil, errorDetails
	}
	contexts, clusterMap := parseCmdOutput(contextDetails)
	for _, context := range contexts {

		podsAndNamespaceCmd := fmt.Sprintf("kubectl get pods -A --context %v --no-headers -o custom-columns=:metadata.name,:metadata.namespace | grep kube-bench", context)
		podsAndNamespaceDetails, err := jumphostObj.RunUnixCommands(podsAndNamespaceCmd)
		if err != nil {
			if strings.Contains(podsAndNamespaceDetails, "The connection to the server") ||
				strings.Contains(podsAndNamespaceDetails, "was refused - did you specify the right host or port?") ||
				strings.Contains(podsAndNamespaceDetails, "Unable to connect to the server") {
				continue
			}
			if cowlibutils.IsEmpty(podsAndNamespaceDetails) {
				podsAndNamespaceDetails = fmt.Sprintf("Kube-bench is not installed in the Kubernetes cluster '%v'", clusterMap[context])
			} else {
				podsAndNamespaceDetails = fmt.Sprintf("Error while listing pods: '%v'.", podsAndNamespaceDetails)
			}
			errorDetails = append(errorDetails, ErrorVO{Error: podsAndNamespaceDetails})
			continue

		}

		podsAndNamespace := parseCmdsOutput(podsAndNamespaceDetails)

		if len(podsAndNamespace) == 0 {
			errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("Kube-bench is not installed in the Kubernetes cluster '%v'.", clusterMap[context])})
			continue
		}

		for _, data := range podsAndNamespace {
			kubebenchcmd := fmt.Sprintf("kubectl logs %v -n %v --context %v", data["pod"], data["Namespace"], context)
			kubebenchDetails, err := jumphostObj.RunUnixCommands(kubebenchcmd)
			if err != nil {
				if strings.HasPrefix(podsAndNamespaceDetails, "The connection to the server") &&
					strings.HasSuffix(podsAndNamespaceDetails, "was refused - did you specify the right host or port?") {

					continue
				}
				errorDetails = append(errorDetails, ErrorVO{Error: fmt.Sprintf("Error while running kubectl logs cmd: '%v'.", podsAndNamespaceDetails)})
				continue

			}
			output = processKubeBenchResult(kubebenchDetails, clusterMap[context])
		}

	}
	return output, errorDetails

}

func mapToStruct(data map[string][]*KubebenchResult) []*KubebenchResult {

	resultdata := make([]*KubebenchResult, 0)
	for _, values := range data {
		resultdata = append(resultdata, values...)

	}
	return resultdata

}

func processCmdOutputData(output map[string]*KubebenchResult) map[string][]*KubebenchResult {
	result := make(map[string][]*KubebenchResult, 0)

	for key, value := range output {
		result[key] = append(result[key], value)
	}
	return result

}

func splitByEmptyNewline(str string) []string {
	strNormalized := regexp.
		MustCompile("\r\n").
		ReplaceAllString(str, "\n")

	return regexp.
		MustCompile(`\n\s*\n`).
		Split(strNormalized, -1)

}

func parseCmdsOutput(input string) (contexts []map[string]string) {

	lines := strings.Split(input, "\n")
	for _, line := range lines {
		if line != "" {
			temp := make(map[string]string, 0)
			wordsTemp := strings.Split(line, " ")
			words := removeEmptyStrings(wordsTemp)
			temp["pod"] = words[0]
			temp["Namespace"] = words[1]
			contexts = append(contexts, temp)
		}
	}
	return contexts
}

func removeEmptyStrings(s []string) []string {
	var r []string
	for _, str := range s {
		if str != "" {
			r = append(r, str)
		}
	}
	return r
}

func parseCmdOutput(input string) ([]string, map[string]string) {

	clusterMap := make(map[string]string, 0)
	var contexts []string

	lines := strings.Split(input, "\n")
	for i := 1; i < len(lines)-1; i++ {
		line := strings.TrimLeft(lines[i], "\t")
		words := strings.Split(line, "\t")
		if len(words) >= 2 {
			clusterMap[words[1]] = words[0]
			contexts = append(contexts, words[1])
		}
	}
	return contexts, clusterMap
}

func processKubeBenchResult(input string, cluster string) map[string]*KubebenchResult {

	lines := strings.Split(input, "\n")

	controls := make(map[string]*KubebenchResult, 0)

	category := make(map[string]string, 0)
	for _, line := range lines {

		lineSplit := strings.Split(line, " ")
		if strings.HasPrefix(line, "[INFO]") {
			category[lineSplit[1]] = strings.Join(lineSplit[2:len(lineSplit)-1], " ")
		}
	}

	for _, line := range lines {

		controlInfo := &KubebenchResult{}
		lineSplit := strings.Split(line, " ")

		evaluatedTime := getCurrentDatetime()

		if strings.HasPrefix(line, "[WARN]") || strings.HasPrefix(line, "[PASS]") ||
			strings.HasPrefix(line, "[FAIL]") {

			controlInfo.System = "kubernetes"
			controlInfo.Source = "kube-bench"
			controlInfo.ResourceID = cluster
			controlInfo.ResourceName = cluster
			controlInfo.ResourceType = "Private cluster"
			controlInfo.ControlNumber = lineSplit[1]
			controlInfo.EvaluatedTime = evaluatedTime
			controlInfo.ComplianceStatusReason = ""
			controlInfo.ValidationStatusCode = ""
			controlInfo.ValidationStatusNotes = ""
			switch lineSplit[0] {
			case "[PASS]":
				controlInfo.ComplianceStatus = "COMPLIANT"
			case "[FAIL]":
				controlInfo.ComplianceStatus = "NON_COMPLIANT"
			case "[WARN]":
				controlInfo.ComplianceStatus = "NON_COMPLIANT"
			}
			controls[lineSplit[1]] = controlInfo
		}
	}

	remediations := splitByEmptyNewline(input)
	for num, values := range remediations {
		if num != len(remediations)-1 {
			if strings.Contains(values, "== Remediations policies ==") {
				values = strings.ReplaceAll(values, "== Remediations policies ==\n", "")
			}
			if _, err := strconv.Atoi(string(values[0])); err == nil && !strings.HasPrefix(string(values), "==") {
				lineSplittemp := strings.Split(values, " ")
				if _, ok := controls[lineSplittemp[0]]; ok {
					temp := strings.Join(strings.Split(strings.Join(lineSplittemp[1:], " "), "\n"), " ")
					controls[lineSplittemp[0]].RemediationSteps = temp
				}
			}
		}
	}
	return controls
}

func (inst *TaskInstance) uploadLogFile(errorList []ErrorVO) (string, error) {
	outputFilePath, err := cowStorage.UploadJSONFile(
		fmt.Sprintf("%v-%v%v", "LogFile", uuid.New().String(), ".json"),
		errorList, inst.SystemInputs,
	)
	if err != nil {
		return "", fmt.Errorf("cannot upload log file to minio: %w", err)
	}
	return outputFilePath, nil
}

func (inst *TaskInstance) uploadOutputFile(outputData []*KubebenchResult, evidenceName string) (string, error) {
	outputFilePath, err := cowStorage.UploadJSONFile(fmt.Sprintf("%v-%v%v", evidenceName, uuid.New().String(), ".json"),
		outputData, inst.SystemInputs,
	)
	if err != nil {
		return "", fmt.Errorf("cannot upload cis benchmark report to minio: %w", err)
	}
	return outputFilePath, nil
}
func getCurrentDatetime() time.Time {
	return time.Now().UTC()
}

type ClientCredential struct {
	AccessToken string `json:"access_token"`
}

type KubebenchResult struct {
	System                   string      `json:"System"`
	Source                   string      `json:"Source"`
	ResourceID               string      `json:"ResourceID"`
	ResourceName             string      `json:"ResourceName"`
	ResourceType             string      `json:"ResourceType"`
	ResourceTags             interface{} `json:"ResourceTags"`
	ParentControlDescription string      `json:"ParentControlDescription"`
	ControlNumber            string      `json:"ControlNumber"`
	ControlDescription       string      `json:"ControlDescription"`
	ValidationStatusCode     string      `json:"ValidationStatusCode"`
	ValidationStatusNotes    string      `json:"ValidationStatusNotes"`
	ComplianceStatus         string      `json:"ComplianceStatus"`
	ComplianceStatusReason   string      `json:"ComplianceStatusReason"`
	RemediationSteps         string      `json:"RemediationSteps"`
	EvaluatedTime            time.Time   `json:"EvaluatedTime"`
	UserAction               string      `json:"UserAction"`
	ActionStatus             string      `json:"ActionStatus"`
	ActionResponseURL        string      `json:"ActionResponseURL"`
}

type RuleConfigVO struct {
	ControlNumber      string `json:"ControlNumber"`
	EvidenceName       string `json:"EvidenceName"`
	ParentControlInfo  string `json:"ParentControlInfo"`
	ControlDescription string `json:"ControlDescription"`
	Compliant          struct {
		ComplianceStatusReason string `json:"ComplianceStatusReason"`
		ValidationStatusCode   string `json:"ValidationStatusCode"`
		ValidationStatusNotes  string `json:"ValidationStatusNotes"`
	} `json:"COMPLIANT"`
	NonCompliant struct {
		ComplianceStatusReason string `json:"ComplianceStatusReason"`
		ValidationStatusCode   string `json:"ValidationStatusCode"`
		ValidationStatusNotes  string `json:"ValidationStatusNotes"`
		Remediation            string `json:"Remediation"`
	} `json:"NON_COMPLIANT"`
}

type ErrorVO struct {
	Error string `json:"Error"`
}
