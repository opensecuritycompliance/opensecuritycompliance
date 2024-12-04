package main

import (
	azure "appconnections/azureappconnector"
	cowStorage "appconnections/minio"
	"cowlibrary/vo"
	"encoding/json"
	"fmt"
	"time"
)

// SecurityAssessment :
func (inst *TaskInstance) SecurityAssessment(inputs *UserInputs, outputs *Outputs) (err error) {
	var errorInfo interface{}
	systemInputs := vo.SystemInputs{}
	systemInputsByteData, err := json.Marshal(inst.SystemInputs)
	if err != nil {
		errorInfo = err
		return nil
	}
	err = json.Unmarshal(systemInputsByteData, &systemInputs)
	if err != nil {
		errorInfo = err
		return nil
	}
	defer func() {
		err = func() error {

			if errorInfo != nil {
				outputs.LogFile, err = cowStorage.UploadJSONFile(fmt.Sprintf("%v-%v%v", "LogFile", time.Now().Unix(), ".json"), errorInfo, systemInputs)
				if err != nil {
					return err
				}
			}

			return nil
		}()
	}()

	azureObj := azure.AzureAppConnector{UserDefinedCredentials: &inst.SystemInputs.UserObject.App.UserDefinedCredentials}
	DefenderAssessmentResponse, err := azureObj.GetDefenderAssessments()
	if err != nil {
		errorInfo = err
		return nil
	}

	outputs.AzureReport, err = cowStorage.UploadJSONFile(fmt.Sprintf("%v-%v%v", "MicrosoftAzureDefenderPolicies", time.Now().Unix(), ".json"), DefenderAssessmentResponse.Value, systemInputs)
	if err != nil {
		errorInfo = err
		return nil
	}

	return nil
}
