package main

import (
	jumphost "appconnections/kubernetes"
	cowStorage "appconnections/minio"
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	cowlibutils "cowlibrary/utils"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/pelletier/go-toml"

	"github.com/ake-persson/mapslice-json"
	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/rego"
	"gopkg.in/yaml.v3"
)

// EvaluateOpaAgainstCollectedManifestData :
func (inst *TaskInstance) EvaluateOpaAgainstCollectedManifestData(inputs *UserInputs, outputs *Outputs) (err error) {

	outputFileNameTemp := inputs.OutputFileName

	errorDetails := []ErrorVO{}
	defer func() {
		if len(errorDetails) > 0 {
			outputs.LogFile, err = inst.uploadLogFile(errorDetails)
		}
	}()

	if !cowlibutils.IsEmpty(inputs.LogFile) {
		previousTaskLog := []ErrorVO{}
		logFileBytes, err := cowStorage.DownloadFile(inputs.LogFile, inst.SystemInputs)
		if err != nil {
			errorDetails = append(errorDetails, ErrorVO{Error: err.Error()})
			return nil
		}

		err = json.Unmarshal(logFileBytes, &previousTaskLog)
		if err != nil {
			errorDetails = append(errorDetails, ErrorVO{Error: err.Error()})
			return nil
		}
		errorDetails = append(errorDetails, previousTaskLog...)
	}

	if cowlibutils.IsEmpty(inputs.DataFile) && len(errorDetails) > 0 {
		return nil
	} else if cowlibutils.IsEmpty(inputs.DataFile) {
		errorDetails = append(errorDetails, ErrorVO{Error: "Data file cannot be empty."})
		return nil
	}

	var queryToEvaluateRego string
	var regoRule []byte

	if inputs.OpaConfigurationFile != "" &&
		!strings.Contains(inputs.OpaConfigurationFile, "MINIO_FILE_PATH") {

		// Extract all the requied fields from the opa yaml file
		// Query , OutputFileName , RegoRule
		queryToEvaluateRego, outputFileNameTemp, regoRule, err = inst.extractOpaTemplateInputs(inputs)
		if err != nil {
			errorDetails = append(errorDetails, ErrorVO{Error: err.Error()})
			return nil
		}
	}
	// Rule input 'Query' has higher priority than opa template data 'Spec.Query'
	// Priority is similar to all the following inputs
	if inputs.Query != "" {
		queryToEvaluateRego = inputs.Query
	}

	if inputs.RegoFile != "" && !strings.Contains(inputs.RegoFile, "MINIO_FILE_PATH") {
		// download the rego file if it is comming as rule input
		// Rule input rego file is priority 0
		// Rego file from opa template is priority 1
		regoRule, err = inst.downloadRegoFile(inputs)
		if err != nil {
			errorDetails = append(errorDetails, ErrorVO{Error: err.Error()})
			return nil
		}
	}

	// check rego policy , query of the rego file and output file name has data
	validationErr := inst.validateRequiredInputs(inputs, regoRule, queryToEvaluateRego, outputFileNameTemp)
	if len(validationErr) > 0 {
		errorDetails = validationErr
		return nil
	}

	// get the  data file from minio
	manifestData, err := inst.downloadResourceFile(inputs)
	if err != nil {
		errorDetails = append(errorDetails, ErrorVO{Error: err.Error()})
		return nil
	}

	// run the rego rule or policy against the collected manifest data
	output, err := inst.evaluateOpaAgainstCollectedManifestData(inputs, manifestData,
		queryToEvaluateRego, regoRule, outputFileNameTemp)
	if err != nil {
		errorDetails = append(errorDetails, ErrorVO{Error: err.Error()})
		return nil
	}

	if outputFileNameTemp == "" {
		outputFileNameTemp = "OpaPolicyForKubernetes"
	}
	outputs.OpaPolicyReport, err = inst.uploadOutputFile(output, outputFileNameTemp)
	if err != nil {
		errorDetails = append(errorDetails, ErrorVO{Error: err.Error()})
		return nil
	}

	return nil
}

func (inst *TaskInstance) validateRequiredInputs(inputs *UserInputs, regoRule []byte,
	queryToEvaluateRego string, outputFileNameTemp string) []ErrorVO {

	errorDetails := []ErrorVO{}
	err := inst.validateInputConfigFile(inputs)
	if err != nil {
		errorDetails = append(errorDetails, ErrorVO{Error: err.Error()})
	}

	if cowlibutils.IsEmpty(inputs.DataFile) || inputs.DataFile == "<<MINIO_FILE_PATH>>" {
		errorDetails = append(errorDetails, ErrorVO{Error: "The DataFile file is missing."})
	}

	errorMsg := "Required input field "
	var requiredFiles []string

	if len(regoRule) == 0 {
		requiredFiles = append(requiredFiles, "RegoFile")
	}

	if cowlibutils.IsEmpty(queryToEvaluateRego) {
		requiredFiles = append(requiredFiles, "Query")
	}
	if cowlibutils.IsEmpty(outputFileNameTemp) {
		requiredFiles = append(requiredFiles, "OutputFileName")
	}

	if len(requiredFiles) > 1 {
		errorMsg = strings.ReplaceAll(errorMsg, "field", "fields")
	}

	errorMsg = errorMsg + strings.Join(requiredFiles, ", ")

	if errorMsg == "Required input field " {
		return errorDetails
	}

	errorMsg = errorMsg + " can not be empty."

	errorDetails = append(errorDetails, ErrorVO{Error: errorMsg})
	return errorDetails
}

func (inst *TaskInstance) evaluateOpaAgainstCollectedManifestData(
	inputs *UserInputs, manifestData interface{},
	queryToEvaluateRego string, regoRule []byte,
	outputFileNameTemp string) ([]interface{}, error) {

	tomlData, err := inst.downloadTomlFile(inputs)
	if err != nil {
		return nil, err
	}
	packageName, err := getPackageNameFromRegoRule(regoRule)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	r := rego.New(
		rego.Query(queryToEvaluateRego),
		rego.Module(fmt.Sprintf("%v.rego", packageName), string(regoRule)))

	// Create a prepared query that can be evaluated.
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}

	output := make([]interface{}, 0)
	switch tempData := manifestData.(type) {
	case []interface{}:
		for _, input_ := range tempData {

			// Execute the prepared query.
			dataToUploadInOutputJsonFileTemp := make([]interface{}, 0)
			inputItems := input_.(map[string]interface{})["items"]
			for _, inputItem := range inputItems.([]interface{}) {

				if inputItem != nil {

					mapsliceOutputObj := mapslice.MapSlice{}

					if inputs.Source == "kubernetes" {

						mapsliceOutputObj = append(mapsliceOutputObj,
							mapslice.MapItem{Key: "System", Value: "kubernetes"})
						mapsliceOutputObj = append(mapsliceOutputObj,
							mapslice.MapItem{Key: "Source", Value: "compliancecow"})

						resourceType, resourceName, namespace := getDataFileDetailsForKubernetes(inputItem)

						mapsliceOutputObj = append(mapsliceOutputObj,
							mapslice.MapItem{Key: "ResourceID", Value: resourceType + "/" + resourceName})

						mapsliceOutputObj = append(mapsliceOutputObj,
							mapslice.MapItem{Key: "ResourceName", Value: resourceName})
						mapsliceOutputObj = append(mapsliceOutputObj,
							mapslice.MapItem{Key: "ResourceType", Value: resourceType})
						mapsliceOutputObj = append(mapsliceOutputObj,
							mapslice.MapItem{Key: "ResourceTags", Value: ""})

						mapsliceOutputObj = append(mapsliceOutputObj,
							mapslice.MapItem{Key: "Namespace", Value: namespace})
						mapsliceOutputObj = append(mapsliceOutputObj,
							mapslice.MapItem{Key: "ClusterType", Value: "Private cluster"})

						if input_.(map[string]interface{})["clusterName"] != nil {
							mapsliceOutputObj = append(mapsliceOutputObj,
								mapslice.MapItem{Key: "ClusterName", Value: input_.(map[string]interface{})["clusterName"].(string)})

						}
					} else if inputs.Source == "aws" {

						mapsliceOutputObj = append(mapsliceOutputObj,
							mapslice.MapItem{Key: "System", Value: "aws"})
						mapsliceOutputObj = append(mapsliceOutputObj,
							mapslice.MapItem{Key: "Source", Value: "compliancecow"})

						if inputItem, ok := inputItem.(map[string]interface{}); ok {

							if resourceIDValue, ok := inputItem["ResourceID"]; ok {
								if valueAsString, ok := resourceIDValue.(string); ok {
									mapsliceOutputObj = append(mapsliceOutputObj,
										mapslice.MapItem{Key: "ResourceID", Value: valueAsString})
								}
							} else {
								mapsliceOutputObj = append(mapsliceOutputObj,
									mapslice.MapItem{Key: "ResourceID", Value: ""})
							}

							if resourceIDValue, ok := inputItem["ResourceName"]; ok {
								if valueAsString, ok := resourceIDValue.(string); ok {
									mapsliceOutputObj = append(mapsliceOutputObj,
										mapslice.MapItem{Key: "ResourceName", Value: valueAsString})
								}
							} else {
								mapsliceOutputObj = append(mapsliceOutputObj,
									mapslice.MapItem{Key: "ResourceName", Value: ""})
							}
							mapsliceOutputObj = append(mapsliceOutputObj,
								mapslice.MapItem{Key: "ResourceType", Value: ""})

							if resourceIDValue, ok := inputItem["Region"]; ok {
								if valueAsString, ok := resourceIDValue.(string); ok {
									mapsliceOutputObj = append(mapsliceOutputObj,
										mapslice.MapItem{Key: "ResourceLocation", Value: valueAsString})
								}
							} else {
								mapsliceOutputObj = append(mapsliceOutputObj,
									mapslice.MapItem{Key: "ResourceLocation", Value: ""})
							}

							mapsliceOutputObj = append(mapsliceOutputObj,
								mapslice.MapItem{Key: "ResourceTags", Value: ""})

							if resourceIDValue, ok := inputItem["AccountID"]; ok {
								if valueAsString, ok := resourceIDValue.(string); ok {
									mapsliceOutputObj = append(mapsliceOutputObj,
										mapslice.MapItem{Key: "AccountID", Value: valueAsString})

								}
							} else {
								mapsliceOutputObj = append(mapsliceOutputObj,
									mapslice.MapItem{Key: "AccountID", Value: ""})

							}
						}
						resourceType := ""
						if input, ok := input_.(map[string]interface{}); ok {
							if resourceIDValue, ok := input["resourceType"]; ok {
								if valueAsString, ok := resourceIDValue.(string); ok {
									resourceType = valueAsString
								}
							}
						}

						for i := range mapsliceOutputObj {

							if strings.Contains((mapsliceOutputObj[i].Key).(string), "ResourceType") {
								mapsliceOutputObj[i].Value = resourceType
								break
							}
						}
					}

					var isRecordCompliant bool
					evaluationNotes := ""

					mapsliceOutputObj = append(mapsliceOutputObj,
						mapslice.MapItem{Key: "RuleName", Value: packageName})

					rs, err := query.Eval(ctx, rego.EvalInput(inputItem))
					if err != nil {
						return nil, err
					}
					if len(rs) != 0 {
						evaluationNotes := ""
						for _, result := range rs {
							for _, expression := range result.Expressions {
								x := reflect.TypeOf(expression.Value)
								switch x.Kind() {
								case reflect.Slice, reflect.Array:
									if sl, ok := expression.Value.([]interface{}); ok {
										evaluationNotesTemp := ""
										for _, val := range sl {
											evaluationNotesTemp = evaluationNotesTemp + val.(string)
										}
										if evaluationNotes == "" || evaluationNotes == " " {
											evaluationNotes = evaluationNotesTemp
										} else {
											evaluationNotes = fmt.Sprintf("\n%v", evaluationNotesTemp)

										}

									}

								case reflect.String:
									if evaluationNotes == "" || evaluationNotes == " " {
										evaluationNotes = fmt.Sprintf("\n%v", expression.Value.(string))
									} else {
										evaluationNotes = expression.Value.(string)
									}

								case reflect.Map:
									if expression.Value.(map[string]interface{})["alertMessage"] != nil {
										if evaluationNotes == "" || evaluationNotes == " " {
											evaluationNotes = fmt.Sprintf("%v", expression.Value.(map[string]interface{})["alertMessage"])
										} else {
											evaluationNotes = fmt.Sprintf("\n%v", fmt.Sprintf("%v", expression.Value.(map[string]interface{})["alertMessage"]))
										}
									}

								default:
									if evaluationNotes == "" || evaluationNotes == " " {
										evaluationNotes = fmt.Sprintf("%v", expression.Value)
									} else {
										evaluationNotes = fmt.Sprintf("\n%v", fmt.Sprintf("%v", expression.Value))
									}
								}

							}

						}
						if evaluationNotes == "" || evaluationNotes == " " {
							isRecordCompliant = true
						}
					} else {
						isRecordCompliant = true
					}

					validationDetails, err := inst.getValidationDetailsFormConfigFile(
						inputs, tomlData, outputFileNameTemp, isRecordCompliant)
					if err != nil {
						return nil, err
					}

					mapsliceOutputObj = append(mapsliceOutputObj,
						mapslice.MapItem{Key: "ValidationStatusCode", Value: validationDetails["ValidationStatusCode"]})
					mapsliceOutputObj = append(mapsliceOutputObj,
						mapslice.MapItem{Key: "ValidationStatusCodeNotes", Value: validationDetails["ValidationStatusCodeNotes"]})
					mapsliceOutputObj = append(mapsliceOutputObj,
						mapslice.MapItem{Key: "ComplianceStatus", Value: validationDetails["ComplianceStatus"]})
					mapsliceOutputObj = append(mapsliceOutputObj,
						mapslice.MapItem{Key: "ComplianceStatusReason", Value: validationDetails["ComplianceStatusReason"]})

					evaluationNotes = strings.TrimPrefix(evaluationNotes, "\n")
					mapsliceOutputObj = append(mapsliceOutputObj,
						mapslice.MapItem{Key: "RemediationNotes", Value: evaluationNotes})

					evaluatedTime := jumphost.GetCurrentDatetime()

					mapsliceOutputObj = append(mapsliceOutputObj,
						mapslice.MapItem{Key: "EvaluatedTime", Value: evaluatedTime})

					if inputs.Source == "kubernetes" {
						mapsliceOutputObj = append(mapsliceOutputObj,
							mapslice.MapItem{Key: "PrNumber", Value: ""})
						mapsliceOutputObj = append(mapsliceOutputObj,
							mapslice.MapItem{Key: "PrStatus", Value: ""})
						mapsliceOutputObj = append(mapsliceOutputObj,
							mapslice.MapItem{Key: "CommitID", Value: ""})
					}
					mapsliceOutputObj = append(mapsliceOutputObj,
						mapslice.MapItem{Key: "TicketCreatedDate", Value: ""})
					mapsliceOutputObj = append(mapsliceOutputObj,
						mapslice.MapItem{Key: "TicketClosedDate", Value: ""})

					mapsliceOutputObj = append(mapsliceOutputObj,
						mapslice.MapItem{Key: "UserAction", Value: ""})

					mapsliceOutputObj = append(mapsliceOutputObj,
						mapslice.MapItem{Key: "ActionStatus", Value: ""})
					mapsliceOutputObj = append(mapsliceOutputObj,
						mapslice.MapItem{Key: "ActionResponseURL", Value: ""})

					dataToUploadInOutputJsonFileTemp = append(dataToUploadInOutputJsonFileTemp, mapsliceOutputObj)
				}
			}

			output = append(output, dataToUploadInOutputJsonFileTemp...)
		}
	}

	return output, nil

}

func (inst *TaskInstance) downloadTomlFile(inputs *UserInputs) (*toml.Tree, error) {

	inputsTomlDataPayload, err := cowStorage.DownloadFile(inputs.ConfigFile, inst.SystemInputs)
	if err != nil {
		return nil, errors.New("Cannot Download file from Minio")
	}

	tomlData, err := toml.LoadBytes(inputsTomlDataPayload)
	if err != nil {
		return nil, fmt.Errorf("Error while downloading input toml file : %v ", err)
	}

	return tomlData, nil
}

func (inst *TaskInstance) getValidationDetailsFormConfigFile(inputs *UserInputs,
	tomlData *toml.Tree, evidenceName string, isRecordCompliant bool) (map[string]string, error) {

	tables := tomlData.Keys()

	if !slices.Contains(tables, evidenceName) {
		return nil, fmt.Errorf("Validation details is missing in config file for '%v' ", evidenceName)
	}
	tableData := tomlData.Get(tables[slices.Index(tables, evidenceName)])

	validationStatusCode, validationStatusNotes, complianceStatus, complianceStatusReason := "", "", "", ""

	if isRecordCompliant {
		validationStatusCode, _ = (tableData.(*toml.Tree)).Get("COMPLIANT.ValidationStatusCode").(string)
		validationStatusNotes, _ = (tableData.(*toml.Tree)).Get("COMPLIANT.ValidationStatusNotes").(string)
		complianceStatus = "COMPLIANT"
		complianceStatusReason, _ = (tableData.(*toml.Tree)).Get("COMPLIANT.ComplianceStatusReason").(string)
	} else {
		validationStatusCode, _ = (tableData.(*toml.Tree)).Get("NON_COMPLIANT.ValidationStatusCode").(string)
		validationStatusNotes, _ = (tableData.(*toml.Tree)).Get("NON_COMPLIANT.ValidationStatusNotes").(string)
		complianceStatus = "NON_COMPLIANT"
		complianceStatusReason, _ = (tableData.(*toml.Tree)).Get("NON_COMPLIANT.ComplianceStatusReason").(string)
	}

	validationDetails := map[string]string{
		"ValidationStatusCode":      validationStatusCode,
		"ValidationStatusCodeNotes": validationStatusNotes,
		"ComplianceStatus":          complianceStatus,
		"ComplianceStatusReason":    complianceStatusReason,
	}

	return validationDetails, nil

}

func (inst *TaskInstance) downloadResourceFile(inputs *UserInputs) (interface{}, error) {
	inputDataFile, err := cowStorage.DownloadFile(inputs.DataFile, inst.SystemInputs)
	if err != nil {
		return nil, err
	}

	var manifestData interface{}

	if strings.HasSuffix(inputs.DataFile, ".yaml") {
		err = yaml.Unmarshal(inputDataFile, &manifestData)
		if err != nil {
			return nil, err
		}
		manifestData = convert(manifestData)

	} else if strings.HasSuffix(inputs.DataFile, ".json") {
		err = json.Unmarshal(inputDataFile, &manifestData)
		if err != nil {
			return nil, err
		}

	} else {
		return nil, errors.New("Invalid file type. Supported types are YAML and JSON.")
	}

	return manifestData, err
}

func (inst *TaskInstance) downloadRegoFile(inputs *UserInputs) ([]byte, error) {

	inputRegoFile, err := cowStorage.DownloadFile(inputs.RegoFile, inst.SystemInputs)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(inputs.RegoFile, ".rego") {
		yamlData := make(map[interface{}]interface{})
		err := readYAMLFromFile(inputRegoFile, &yamlData)
		if err != nil {
			return nil, err
		}
		inputRegoFile = []byte(getRego(yamlData))
	}

	return inputRegoFile, nil
}

func (inst *TaskInstance) extractOpaTemplateInputs(inputs *UserInputs) (string, string, []byte, error) {

	var queryToEvaluateRego string
	var regoRule []byte
	opaConfigurationVO := OpaConfigurationVO{}
	var outputFileNameTemp string

	fileContent, err := cowStorage.DownloadFile(inputs.OpaConfigurationFile, inst.SystemInputs)
	if err != nil {
		return "", "", nil, err
	}

	var opaConfigurationFileContent []byte

	var regoDataFromZip []byte

	if strings.HasSuffix(inputs.OpaConfigurationFile, ".zip") {

		opaConfigurationFileContent, regoDataFromZip, err = extractRegoFromZipFile(fileContent)
		if err != nil {
			return "", "", nil, err
		}

	} else {
		opaConfigurationFileContent = fileContent
	}

	err = yaml.Unmarshal(opaConfigurationFileContent, &opaConfigurationVO)
	if err != nil {
		return "", "", nil, err
	}

	queryToEvaluateRego = opaConfigurationVO.Spec.Query

	if len(opaConfigurationVO.Spec.Outputs.Files) > 0 &&
		opaConfigurationVO.Spec.Outputs.Files[0].Name != "" {

		outputFileNameTemp = opaConfigurationVO.Spec.Outputs.Files[0].Name
	}

	switch opaConfigurationVO.Spec.Rego.Type {
	case "regostring":
		regoRule = []byte(opaConfigurationVO.Spec.Rego.Regostring)

	case "localfile":
		if opaConfigurationVO.Spec.Rego.Localfile != "" &&
			!strings.HasSuffix(opaConfigurationVO.Spec.Rego.Localfile, ".rego") {

			regoRuleTemp, err := base64.StdEncoding.DecodeString(opaConfigurationVO.Spec.Rego.Localfile)
			if err != nil {
				return "", "", nil, err
			}
			regoRule = regoRuleTemp
		} else {
			regoRule = regoDataFromZip
		}
	default:
		return "", "", nil, errors.New("invalid RegoType. It should be any one of the followings 'regostring','networkfile' and 'localfile,")
	}

	return queryToEvaluateRego, outputFileNameTemp, regoRule, nil
}

func extractRegoFromZipFile(fileContent []byte) ([]byte, []byte, error) {

	var opaConfigurationFileContent []byte
	var regoDataFromZip []byte

	zipReader, err := zip.NewReader(bytes.NewReader(fileContent), int64(len(fileContent)))
	if err != nil {
		return opaConfigurationFileContent, regoDataFromZip, err
	}
	for _, file := range zipReader.File {

		if strings.HasSuffix(file.Name, ".yaml") && !strings.Contains(file.Name, "__MACOSX") {
			zipFile, err := file.Open()
			if err != nil {
				return opaConfigurationFileContent, regoDataFromZip, err
			}
			defer zipFile.Close()
			contents, err := ioutil.ReadAll(zipFile)
			if err != nil {
				return opaConfigurationFileContent, regoDataFromZip, err
			}
			opaConfigurationFileContent = contents

		} else if strings.HasSuffix(file.Name, ".rego") && !strings.Contains(file.Name, "__MACOSX") {

			zipFile, err := file.Open()
			if err != nil {
				return opaConfigurationFileContent, regoDataFromZip, err
			}
			defer zipFile.Close()
			contents, err := ioutil.ReadAll(zipFile)
			if err != nil {
				return opaConfigurationFileContent, regoDataFromZip, err
			}
			regoDataFromZip = contents
		}

	}

	return opaConfigurationFileContent, regoDataFromZip, nil
}

func (inst *TaskInstance) validateInputConfigFile(inputs *UserInputs) error {

	if cowlibutils.IsEmpty(inputs.ConfigFile) || inputs.ConfigFile == "<<MINIO_FILE_PATH>>" {
		return errors.New("The input Config file is missing. Please upload a valid Config file")
	}

	fileExtension := filepath.Ext(inputs.ConfigFile)
	if fileExtension != ".toml" {
		return fmt.Errorf("The provided file type is not supported. Please upload a file with the .toml extension. The uploaded file is of an unsupported type (%s)", fileExtension)
	}
	return nil
}

func getDataFileDetailsForKubernetes(dataFile interface{}) (string, string, string) {

	var resourceType string
	var resourceName string
	var namespace string
	tempData := dataFile.(map[string]interface{})
	if tempData["kind"] != nil {
		resourceType = tempData["kind"].(string)
	}
	if tempData["metadata"].(map[string]interface{})["name"] != nil {
		resourceName = tempData["metadata"].(map[string]interface{})["name"].(string)
	}
	if tempData["metadata"].(map[string]interface{})["namespace"] != nil {
		namespace = tempData["metadata"].(map[string]interface{})["namespace"].(string)
	}
	return resourceType, resourceName, namespace

}

func getPackageNameFromRegoRule(regoFile []byte) (string, error) {

	var packageName string
	fileScanner := bufio.NewScanner(bytes.NewBuffer(regoFile))
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		res := strings.Split(fileScanner.Text(), " ")
		packageName = res[len(res)-1]
		if res[0] == "package" {
			break
		}
	}

	return packageName, nil
}

func getRego(yamlData map[interface{}]interface{}) string {
	for k, v := range yamlData {
		kString, ok := k.(string)
		if !ok {
			continue
		}
		if kString == "rego" {
			vString, ok := v.(string)
			if ok {
				return vString
			}
			return ""
		}
		objectType := reflect.TypeOf(v).String()
		if objectType == "map[interface {}]interface {}" || objectType == "map[string]interface {}" {
			data := getRego(v.(map[interface{}]interface{}))
			if data != "" {
				return data
			}
		}
		if objectType == "[]interface {}" {
			for _, child := range v.([]interface{}) {
				if object, ok := child.(map[interface{}]interface{}); ok {
					data := getRego(object)
					if data != "" {
						return data
					}
				}
			}
		}
	}
	return ""
}

func FilterIncludeExcludeCriteria(include, exclude string) (map[string][]string, map[string][]string) {
	includeStrings := strings.Split(include, "/")
	excludeStrings := strings.Split(exclude, "/")

	includeresources, excluderesources := make(map[string][]string), make(map[string][]string)

	for i := 0; i < len(includeStrings); i = i + 2 {
		var includevalues []string
		if includeStrings[i] == "" {
			i = i - 1
			continue
		}
		includekey := strings.Split(includeStrings[i], ",")
		if i+1 < len(includeStrings) {
			includevalues = strings.Split(includeStrings[i+1], ",")
		} else {
			includevalues = append(includevalues, "*")
		}
		for _, key := range includekey {
			includeresources[strings.ToLower(key)] = includevalues

		}

	}

	for i := 0; i < len(excludeStrings)-1; i = i + 2 {
		if excludeStrings[i] == "" {
			i = i - 1
			continue
		}

		excludekey := strings.Split(excludeStrings[i], ",")
		excludevalues := strings.Split(excludeStrings[i+1], ",")

		for _, key := range excludekey {
			excluderesources[key] = excludevalues

		}

	}
	return includeresources, excluderesources

}

func readYAMLFromFile(yamlDataBytes []byte, data interface{}) error {

	err := yaml.Unmarshal(yamlDataBytes, data)
	if err != nil {
		return err
	}
	return nil
}

func convert(yamlData interface{}) interface{} {

	switch tempData := yamlData.(type) {
	case map[interface{}]interface{}:
		jsonData := map[string]interface{}{}
		for key, value := range tempData {
			jsonData[key.(string)] = convert(value)
		}
		return jsonData
	case []interface{}:
		for index, value := range tempData {
			tempData[index] = convert(value)
		}
	}
	return yamlData
}

func (inst *TaskInstance) uploadLogFile(errorList []ErrorVO) (string, error) {

	auditFileNameWithUUID := fmt.Sprintf("%v-%v%v", "LogFile", uuid.New().String(), ".json")
	outputFilePath, err := cowStorage.UploadJSONFile(
		auditFileNameWithUUID, errorList, inst.SystemInputs)
	if err != nil {
		return "", fmt.Errorf("cannot upload log file to minio: %w", err)
	}
	return outputFilePath, nil
}

func (inst *TaskInstance) uploadOutputFile(outputData interface{},
	outputFileNameTemp string) (string, error) {

	reportFileNameWithUUID := fmt.Sprintf("%v-%v%v", outputFileNameTemp, uuid.New().String(), ".json")
	outputFilePath, err := cowStorage.UploadJSONFile(reportFileNameWithUUID, outputData, inst.SystemInputs)
	if err != nil {
		return "", fmt.Errorf("cannot upload access key rotation data to minio: %w", err)
	}
	return outputFilePath, nil
}

type OpaConfigurationVO struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name        string `yaml:"name"`
		Purpose     string `yaml:"purpose"`
		Description string `yaml:"description"`
	} `yaml:"metadata"`
	Spec struct {
		Format       string `yaml:"format"`
		Ruleselector string `yaml:"ruleselector"`
		Source       string `yaml:"source"`
		Query        string `yaml:"query"`
		Rego         struct {
			Type        string `yaml:"type"`
			Regostring  string `yaml:"regostring"`
			Networkfile string `yaml:"networkfile"`
			Localfile   string `yaml:"localfile"`
		} `yaml:"rego"`
		IncludeCriteria string `yaml:"includeCriteria"`
		Excludecriteria string `yaml:"excludecriteria"`
		Outputs         struct {
			Files []struct {
				Name      string `yaml:"name"`
				Shortname string `yaml:"shortname"`
			} `yaml:"files"`
		} `yaml:"outputs"`
	} `yaml:"spec"`
}

type ErrorVO struct {
	Error string `json:"Error"`
}
