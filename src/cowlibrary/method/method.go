package method

import (
	"cowlibrary/utils"
	"cowlibrary/vo"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v2"

	"github.com/fatih/color"
)

func CreateMethod(yamlFilepath string, additionalInfo *vo.AdditionalInfo) error {

	yamlFileInfo, err := os.Stat(yamlFilepath)
	if err != nil || yamlFileInfo.IsDir() {
		if err != nil && os.IsNotExist(err) {
			if _, err = os.Create(yamlFilepath); err != nil {
				return err
			}
		} else {
			return errors.New("cannot find the file")
		}

	}

	byts, err := os.ReadFile(yamlFilepath)
	if err != nil || yamlFileInfo.IsDir() {
		return err
	}

	method := &vo.Method{}

	err = yaml.Unmarshal(byts, method)
	if err != nil || yamlFileInfo.IsDir() {
		return err
	}

	err = UpsertMethod(method)
	if err == nil {
		color.Green("%s method successfully added in the repo ", method.Metadata.Name)
		fmt.Println()
	}

	return err

}

func UpsertMethod(methodInfo *vo.Method) error {
	methods, err := GetAvailableMethods(methodInfo.Spec.MethodCatalogFilePath)
	if err != nil {
		return err
	}

	isMethodAlreadyPresented := false
	for _, method := range methods {
		if method.Method == methodInfo.Metadata.Name {
			isMethodAlreadyPresented = true
			method.Method = methodInfo.Metadata.Name
			method.Imports = methodInfo.Spec.Imports
			method.MethodCall = methodInfo.Spec.MethodCall
			method.Outputs = methodInfo.Spec.Outputs
			method.MethodCode = methodInfo.Spec.MethodCode
		}
	}

	if !isMethodAlreadyPresented {
		codeCatalog := &vo.CodeCatalog{Method: methodInfo.Metadata.Name, Imports: methodInfo.Spec.Imports, MethodCall: methodInfo.Spec.MethodCall,
			Outputs: methodInfo.Spec.Outputs, MethodCode: methodInfo.Spec.MethodCode}
		methods = append(methods, codeCatalog)
	}

	return UpdateMethods(methodInfo.Spec.MethodCatalogFilePath, methods)

}

func GetAvailableMethods(catalogFile string) ([]*vo.CodeCatalog, error) {

	fileByts := make([]byte, 0)
	if utils.IsNotEmpty(catalogFile) {
		byts, err := os.ReadFile(catalogFile)
		if err != nil {
			return nil, errors.New("cannot find the file")
		}
		fileByts = byts
	} else {

		fileInfo := utils.ReadFileHelperWithExtLookUpAndReturnFileInfo("methodCatalog", "json", "catalog", 4, 0)
		if fileInfo == nil {
			return nil, errors.New("cannot find the file")
		}
		fileByts = fileInfo.FileByts
	}

	methods := make([]*vo.CodeCatalog, 0)
	err := json.Unmarshal(fileByts, &methods)
	if err != nil {
		return nil, err
	}
	return methods, err
}

func UpdateMethods(catalogFilePath string, methods []*vo.CodeCatalog) error {

	byts, err := json.MarshalIndent(methods, "", "  ")

	if err != nil {
		return err
	}

	return os.WriteFile(catalogFilePath, byts, os.ModePerm)

}
