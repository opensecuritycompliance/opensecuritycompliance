package opautils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	resources "github.com/kubescape/opa-utils/resources"
	"github.com/open-policy-agent/opa/v1/rego"
)

func AppendDependencyModules(
	regoOptions []func(*rego.Rego),
) []func(*rego.Rego) {

	dependencyModules := resources.LoadRegoModules()
	fmt.Println("Dependency modules loaded:", len(dependencyModules))
	for name := range dependencyModules {
		fmt.Println("MODULE:", name)
	}
	for moduleName, moduleContent := range dependencyModules {
		fmt.Println("Appending module:", moduleName)
		regoOptions = append(
			regoOptions,
			rego.Module(
				moduleName+".rego",
				moduleContent,
			),
		)
	}

	return regoOptions
}

func SaveJSONLocally(filePath string, obj interface{}) error {
	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, data, 0644)
}
