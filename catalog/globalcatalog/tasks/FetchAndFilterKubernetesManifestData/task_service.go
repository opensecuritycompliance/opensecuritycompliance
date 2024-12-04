package main

import (
	jumphost "appconnections/kubernetes"
	cowStorage "appconnections/minio"
	"archive/zip"
	"bytes"
	cowlibutils "cowlibrary/utils"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
)

// FetchAndFilterKubernetesManifestData :
func (inst *TaskInstance) FetchAndFilterKubernetesManifestData(inputs *UserInputs, outputs *Outputs) (err error) {

	errorDetails := []ErrorVO{}

	defer func() {
		if len(errorDetails) > 0 {
			outputs.LogFile, err = inst.uploadLogFile(errorDetails)
		}
	}()

	var includeCriteria string
	var excludeCriteria string

	if inputs.OpaConfigurationFile != "" &&
		!strings.Contains(inputs.OpaConfigurationFile, "MINIO_FILE_PATH") {

		includeCriteria, excludeCriteria, err = inst.extractIncAndExcFromOpaTemplate(inputs)
		if err != nil {
			errorDetails = append(errorDetails, ErrorVO{Error: err.Error()})
			return nil
		}
	}

	if inputs.IncludeCriteria != "" {
		includeCriteria = inputs.IncludeCriteria
	}

	if inputs.ExcludeCriteria != "" {
		excludeCriteria = inputs.ExcludeCriteria
	}

	if cowlibutils.IsEmpty(includeCriteria) {
		errorDetails = append(errorDetails, ErrorVO{Error: "IncludeCriteria cannot be empty."})
		return nil
	}

	include, exclude := FilterIncludeExcludeCriteria(includeCriteria, excludeCriteria)

	jumphostObj := jumphost.Kubernetes{
		UserDefinedCredentials: &inst.SystemInputs.UserObject.App.UserDefinedCredentials,
		AppURL:                 inst.SystemInputs.UserObject.App.ApplicationURL,
	}

	output, err := inst.runKubernetesCommandForJumpHost(jumphostObj, include, exclude, inputs)
	if err != nil {
		errorDetails = append(errorDetails, ErrorVO{Error: err.Error()})
		if len(output) == 0 {
			return nil
		}
	}

	if len(output) == 0 {
		errorDetails = append(errorDetails, ErrorVO{
			Error: "Could not retrieve details based on the provided credentials or query."})
		return nil
	}

	outputs.Source = "kubernetes"

	outputs.DataFile, err = inst.uploadOutputFile(output)
	if err != nil {
		errorDetails = append(errorDetails, ErrorVO{Error: err.Error()})
		return nil
	}

	return nil

}

func (inst *TaskInstance) extractIncAndExcFromOpaTemplate(inputs *UserInputs) (string, string, error) {

	var includeCriteria string
	var excludeCriteria string

	fileContent, err := cowStorage.DownloadFile(inputs.OpaConfigurationFile, inst.SystemInputs)
	if err != nil {
		return includeCriteria, excludeCriteria, err
	}

	var opaConfigurationFileContent []byte

	opaConfigurationVO := OpaConfigurationVO{}

	if strings.HasSuffix(inputs.OpaConfigurationFile, ".zip") {

		zipReader, err := zip.NewReader(bytes.NewReader(fileContent), int64(len(fileContent)))
		if err != nil {
			return includeCriteria, excludeCriteria, err
		}
		for _, file := range zipReader.File {

			if strings.HasSuffix(file.Name, ".yaml") && !strings.Contains(file.Name, "__MACOSX") {
				zipFile, err := file.Open()
				if err != nil {
					return includeCriteria, excludeCriteria, err
				}
				defer zipFile.Close()
				contents, err := io.ReadAll(zipFile)
				if err != nil {
					return includeCriteria, excludeCriteria, err
				}
				opaConfigurationFileContent = contents
			}
		}

	} else {
		opaConfigurationFileContent = fileContent
	}

	err = yaml.Unmarshal(opaConfigurationFileContent, &opaConfigurationVO)
	if err != nil {
		return includeCriteria, excludeCriteria, err
	}

	if opaConfigurationVO.Spec.Source != "kubernetes" {
		return includeCriteria, excludeCriteria, errors.New("Wrong source type")
	}

	includeCriteria = opaConfigurationVO.Spec.IncludeCriteria
	excludeCriteria = opaConfigurationVO.Spec.Excludecriteria

	return includeCriteria, excludeCriteria, nil
}

func (inst *TaskInstance) runKubernetesCommandForJumpHost(jumphostObj jumphost.Kubernetes,
	include map[string][]string, exclude map[string][]string,
	inputs *UserInputs) ([]NewCmdOutput, error) {

	// filter cluster using include and exclude criteria
	contexts, clusterMap, err := inst.applyFiltersToCluster(jumphostObj, include, exclude, inputs)
	if err != nil {
		return nil, err
	}

	var errorMessage []string

	tempNewCmdOutput := []NewCmdOutput{}

	for _, context := range contexts {

		// filter namespace using include and exclude criteria
		filteredNamespaces, invalidNamespaces, excludeNamespace, err := applyFiltersToNamespace(
			jumphostObj, context, clusterMap, include, exclude)
		if err != nil {
			return nil, err
		}
		if len(invalidNamespaces) > 0 {
			errorMessage = append(errorMessage,
				(invalidNamespacesError(invalidNamespaces, clusterMap[context]))...)
		}

		// filter the resource using include criteria ,
		// The exclude resource filter is implemented after the data is fetched from Kubernetes.
		var includeResources []string
		for key := range include {
			if key != "cluster" && key != "namespace" {
				includeResources = append(includeResources, key)
			}
		}

		for _, namespace := range filteredNamespaces {
			if len(includeResources) > 0 {
				for _, resource := range includeResources {
					if !slices.Contains(excludeNamespace, namespace) {
						command := "kubectl get " + resource + " -n " + namespace + " --context=" + context + " -o json "
						getResourceCmdOutput, invalidResource, err := inst.runKubernetesCommand(jumphostObj, inputs,
							clusterMap[context], namespace, resource, include, exclude, command)
						if err != nil {
							if err.Error() == "continue" {
								continue
							} else if err.Error() == "the server doesn't have a resource type" {
								errTemp := fmt.Sprintf("The server doesn't have a resource type '%v' in '%v' namespace.", resource, namespace)
								errorMessage = append(errorMessage, errTemp)
								continue
							} else {
								return nil, err
							}
						}
						if len(invalidResource) > 0 {
							errorMessage = append(errorMessage,
								(invalidResourceError(invalidResource, namespace, clusterMap[context]))...)
						}
						if getResourceCmdOutput.Items != nil {
							tempNewCmdOutput = append(tempNewCmdOutput, getResourceCmdOutput)
						}
					}
				}
			} else {
				command := "kubectl get namespace " + namespace + " --context " + context + " -o json"
				getResourceCmdOutput, _, err := inst.runKubernetesCommand(jumphostObj, inputs,
					clusterMap[context], namespace, "", include, exclude, command)
				if err != nil {
					if err.Error() == "continue" {
						continue
					} else if err.Error() == "the server doesn't have a resource type" {
						errTemp := fmt.Sprintf("The server doesn't have a namespace '%v' .", namespace)
						errorMessage = append(errorMessage, errTemp)
						continue
					} else {
						return nil, err
					}
				}
				if getResourceCmdOutput.Items != nil {
					tempNewCmdOutput = append(tempNewCmdOutput, getResourceCmdOutput)
				}
			}
		}
	}

	if len(errorMessage) > 0 {
		return tempNewCmdOutput, errors.New(strings.Join(errorMessage, "\n"))
	}

	return tempNewCmdOutput, nil

}

func applyFilters(resource string, filters map[string][]string, cluster, namespace string) bool {

	if _, ok := filters[resource]; ok &&
		(slices.Contains(filters["cluster"], "*") || slices.Contains(filters["cluster"], cluster)) &&
		(slices.Contains(filters["namespace"], "*") || slices.Contains(filters["namespace"], namespace)) {
		return true
	}

	return false
}

func invalidResourceError(invalidResource []string, namespace string, cluster string) []string {

	var errorMessage []string

	for _, resource := range invalidResource {

		errorMessage = append(errorMessage,
			fmt.Sprintf("'%v' does not exist in namespace '%v' within cluster '%v'.", resource, namespace, cluster))

	}
	return errorMessage
}

func invalidNamespacesError(invalidNamespaces []string, cluster string) []string {

	var errorMessage []string

	for _, namespace := range invalidNamespaces {

		errorMessage = append(errorMessage,
			fmt.Sprintf("Namespace '%v' is not exist in '%v' cluster", namespace, cluster))

	}
	return errorMessage
}

func filterInvalidIncludedResources(jumphostObj jumphost.Kubernetes, cmd string,
	include map[string][]string, resource string) ([]string, error) {

	var invalidResource []string
	newCmd := strings.ReplaceAll(cmd, "json", "custom-columns=:metadata.name")
	cmdOutput, err := jumphostObj.RunUnixCommandsWithRetry(newCmd, 2)
	if err != nil {
		return invalidResource, err
	}

	var resources []string
	lines := strings.Split(cmdOutput, "\n")
	for i := 0; i < len(lines)-1; i++ {
		line := strings.TrimLeft(lines[i], "\t")
		fields := strings.Fields(line)
		if len(fields) != 0 {
			resources = append(resources, fields[0])
		}
	}

	for _, inc := range include[resource] {
		if !slices.Contains(resources, inc) {
			invalidResource = append(invalidResource, inc)
		}
	}

	return invalidResource, nil
}

func (inst *TaskInstance) runKubernetesCommand(jumphostObj jumphost.Kubernetes, inputs *UserInputs,
	cluster string, namespace string, resource string, include map[string][]string,
	exclude map[string][]string, cmd string) (NewCmdOutput, []string, error) {

	newCmdOutput := NewCmdOutput{}

	var invalidResource []string
	if !strings.Contains(cmd, "kubectl get namespace ") {
		var err error
		if !(len(include[resource]) == 1 && include[resource][0] == "*") {
			invalidResource, err = filterInvalidIncludedResources(jumphostObj, cmd, include, resource)
			if err != nil {
				return newCmdOutput, invalidResource, err
			}

			if (len(include[resource]) > 0 && include[resource][0] != "*") &&
				len(include[resource]) == len(invalidResource) {

				return newCmdOutput, invalidResource, err
			}
		}

	}

	cmdOutput, err := jumphostObj.RunUnixCommandsWithRetry(cmd, 2)
	if strings.Contains(cmdOutput, "Unable to connect to the server") {
		return newCmdOutput, invalidResource, errors.New("continue")
	}

	if err != nil {
		if strings.Contains(cmdOutput, "the server doesn't have a resource type") {
			return newCmdOutput, invalidResource, errors.New("the server doesn't have a resource type")
		}
		if cmdOutput == "" {
			return newCmdOutput, invalidResource, err
		}

		return newCmdOutput, invalidResource, fmt.Errorf(cmdOutput)

	}
	if !strings.Contains(cmdOutput, "items: []") {

		if strings.Contains(cmd, "kubectl get namespace ") {
			namespaceData, err := formateNamespaceManifestData(cmdOutput)
			if err != nil {
				return newCmdOutput, invalidResource, err
			}
			newCmdOutput.Items = namespaceData

		} else {
			err := json.Unmarshal([]byte(cmdOutput), &newCmdOutput)
			if err != nil {
				return newCmdOutput, invalidResource, err
			}

			var data interface{}
			if applyFilters(resource, include, cluster, namespace) ||
				applyFilters(resource, exclude, cluster, namespace) {

				filteredResourceData, err := applyFiltersToResources(newCmdOutput.Items, include, exclude)
				if err != nil {
					return newCmdOutput, invalidResource, err
				}
				if len(filteredResourceData) == 0 {
					return newCmdOutput, invalidResource, errors.New("continue")
				}

				data = filteredResourceData
			} else {
				data = newCmdOutput.Items
			}

			newCmdOutput.Items = data
		}

		newCmdOutput.ClusterName = cluster
		newCmdOutput.Namespace = namespace
	}

	if len(invalidResource) > 1 {
		return newCmdOutput, invalidResource, nil
	}

	return newCmdOutput, invalidResource, nil
}

// Add include and exclude filters
func (inst *TaskInstance) applyFiltersToCluster(jumphostObj jumphost.Kubernetes,
	include map[string][]string, exclude map[string][]string,
	inputs *UserInputs) ([]string, map[string]string, error) {

	clustercommand := fmt.Sprintf("%v%v", "kubectl config view -o jsonpath=", "'{\"Cluster\\tContexts\\n\"}{range .contexts[*]}{.context.cluster}{\"\\t\"}{.name}{\"\\n\"}{end}'")
	if clusters, ok := include["cluster"]; ok {
		for _, cluster := range clusters {
			if cluster == "*" {
				continue
			} else if strings.Contains(clustercommand, " | grep '") {
				clustercommand = clustercommand + `\|` + cluster

			} else {
				clustercommand = clustercommand + " | grep '" + cluster
			}
		}
	}
	if strings.Contains(clustercommand, " | grep") {
		clustercommand = clustercommand + "'"
	}
	if len(exclude) == 1 {
		if clusters, ok := exclude["cluster"]; ok {
			for _, cluster := range clusters {

				if strings.Contains(clustercommand, " | grep -v '") {
					clustercommand = clustercommand + `\|` + cluster

				} else {
					clustercommand = clustercommand + " | grep -v '" + cluster

				}
			}

		}
	}

	var cmdOutput string
	cmdOutput, err := jumphostObj.RunUnixCommandsWithRetry(clustercommand, 2)
	if err != nil {
		if clusters, ok := include["cluster"]; ok && (len(clusters) == 1 && clusters[0] == "*") {
			return nil, nil, errors.New("Error while listing clusters")
		} else {
			return nil, nil, fmt.Errorf("Error while listing clusters [ %v ]", strings.Join(include["cluster"], ","))
		}

		if strings.Contains(cmdOutput, "unexpected EOF while looking for matching `''") {
			return []string{}, nil, errors.New("No records found for the provided credentials or specified query")
		}

	}
	contexts, clusterMap := parseClusterRawCmdOutput(cmdOutput)
	return contexts, clusterMap, nil

}

// Add include and exclude filters
func applyFiltersToNamespace(jumphostObj jumphost.Kubernetes, context string,
	clusterMap map[string]string, include map[string][]string,
	exclude map[string][]string) ([]string, []string, []string, error) {

	var availableNamespaces []string
	command := "kubectl get namespaces --context=" + context

	cmdOutput, err := jumphostObj.RunUnixCommandsWithRetry(command, 2)
	if err != nil {
		return nil, nil, nil, err
	}

	availableNamespaces = getNamespaceList(cmdOutput)

	var includeNamespace []string

	if namespaces, ok := include["namespace"]; ok {
		includeNamespace = namespaces
	}

	var excludeNamespace []string
	if len(exclude) == 2 {
		if slices.Contains(exclude["cluster"], clusterMap[context]) ||
			(len(exclude["cluster"]) == 1 && exclude["cluster"][0] == "*") {

			if namespaces, ok := exclude["namespace"]; ok {
				excludeNamespace = namespaces
			}
		}
	}
	var invalidNamespaces []string
	var level1FilteredNamespaces []string

	if len(includeNamespace) == 1 && includeNamespace[0] == "*" {
		level1FilteredNamespaces = availableNamespaces
	} else {
		for _, includeNS := range includeNamespace {

			if !slices.Contains(availableNamespaces, includeNS) {
				invalidNamespaces = append(invalidNamespaces, includeNS)
			} else {
				level1FilteredNamespaces = append(level1FilteredNamespaces, includeNS)
			}
		}
	}
	var filteredNamespaces []string

	if !(len(excludeNamespace) == 1 && excludeNamespace[0] == "*") {
		for _, namespace := range level1FilteredNamespaces {
			if !slices.Contains(excludeNamespace, namespace) {
				filteredNamespaces = append(filteredNamespaces, namespace)
			}
		}
	}

	return filteredNamespaces, invalidNamespaces, excludeNamespace, nil

}

// Add include and exclude filters
func applyFiltersToResources(jsonData_ interface{}, include map[string][]string,
	exclude map[string][]string) ([]interface{}, error) {

	jsonData := jsonData_.([]interface{})
	filteredJsonData := make([]interface{}, 0)

	for _, Values := range jsonData {

		var kind string
		var resourceName string

		if Valuestemp := Values.(map[string]interface{}); Valuestemp != nil {
			if metaData := Valuestemp["metadata"].(map[string]interface{}); metaData != nil {

				if resourceNameTemp, ok := metaData["name"]; ok {
					resourceName = resourceNameTemp.(string)
				}
			}

			if kindTemp, ok := Valuestemp["kind"]; ok {
				kind = kindTemp.(string)
			}
		}

		kind = normalizeString(kind)

		includeResource := false
		for includeKey, includeValues := range include {
			if normalizeString(includeKey) == kind {
				if len(includeValues) == 1 && includeValues[0] == "*" {
					includeResource = true
					break
				} else if slices.Contains(includeValues, resourceName) {
					includeResource = true
					break
				}
			}
		}

		excludeResource := false
		for excludeKey, excludeValues := range exclude {
			if excludeKey == kind {
				if len(excludeValues) == 1 && excludeValues[0] == "*" {
					excludeResource = true
					break
				} else if slices.Contains(excludeValues, resourceName) {
					excludeResource = true
					break
				}

			}
		}
		if includeResource && !excludeResource {
			filteredJsonData = append(filteredJsonData, Values)
		}
	}

	return filteredJsonData, nil
}

func parseClusterRawCmdOutput(input string) ([]string, map[string]string) {
	clusterMap := make(map[string]string, 0)
	var contexts []string

	lines := strings.Split(input, "\n")
	for i := 0; i < len(lines)-1; i++ {
		line := strings.TrimLeft(lines[i], "\t")
		fields := strings.Fields(line)
		if slices.Contains(fields, "Cluster") && slices.Contains(fields, "Contexts") {
			continue
		}
		if len(fields) >= 2 {
			clusterMap[fields[1]] = fields[0]
			contexts = append(contexts, fields[1])
		}
	}
	return contexts, clusterMap
}

func getNamespaceList(input string) []string {
	lines := strings.Split(input, "\n")
	var names []string

	for _, line := range lines {
		// Skip the header line
		if strings.HasPrefix(line, "NAME") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			names = append(names, fields[0])
		}
	}

	return names
}

func formateNamespaceManifestData(cmdOutput string) ([]interface{}, error) {
	var opaConfigurationVO map[string]interface{}

	var processedNamespaceData []interface{}

	err := json.Unmarshal([]byte(cmdOutput), &opaConfigurationVO)
	if err != nil {
		return processedNamespaceData, err
	}

	processedNamespaceData = append(processedNamespaceData, opaConfigurationVO)
	return processedNamespaceData, nil

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
			includeresources[key] = includevalues

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
	if _, ok := includeresources["cluster"]; !ok {
		includeresources["cluster"] = append(includeresources["cluster"], "*")
	}
	if _, ok := includeresources["namespace"]; !ok {
		includeresources["namespace"] = append(includeresources["namespace"], "*")
	}

	return includeresources, excluderesources

}

func normalizeString(s string) string {
	s = strings.ToLower(s)
	s = strings.TrimSpace(s)
	return s
}

func (inst *TaskInstance) uploadLogFile(errorList []ErrorVO) (string, error) {
	auditFileNameWithUUID := fmt.Sprintf("%v-%v%v", "LogFile", uuid.New().String(), ".json")
	outputFilePath, err := cowStorage.UploadJSONFile(auditFileNameWithUUID, errorList, inst.SystemInputs)
	if err != nil {
		return "", fmt.Errorf("cannot upload log file to minio: %w", err)
	}
	return outputFilePath, nil
}

func (inst *TaskInstance) uploadOutputFile(outputData []NewCmdOutput) (string, error) {
	reportFileNameWithUUID := fmt.Sprintf("%v-%v%v", "Resource", uuid.New().String(), ".json")
	outputFilePath, err := cowStorage.UploadJSONFile(reportFileNameWithUUID, outputData, inst.SystemInputs)
	if err != nil {
		return "", fmt.Errorf("cannot upload k8s manifest data to minio: %w", err)
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
			Type       string `yaml:"type"`
			Regostring string `yaml:"regostring"`
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

type NewCmdOutput struct {
	Items             interface{} `json:"items"`
	SubscriptionID    string      `json:"subscriptionID"`
	SubscriptionName  string      `json:"subscriptionName"`
	ResourceGroupName string      `json:"resourceGroupName"`
	ClusterName       string      `json:"clusterName"`
	Namespace         string      `json:"namespace"`
	Source            string      `json:"source"`
}
type ErrorVO struct {
	Error string `json:"Error"`
}
