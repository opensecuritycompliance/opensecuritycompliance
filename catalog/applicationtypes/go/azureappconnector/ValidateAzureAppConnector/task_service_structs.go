// This file is autogenerated. Modify as per your task needs.
package main

import (
	azureappconnector "applicationtypes/azureappconnector"
)

type UserInputs struct {
	azureappconnector.AzureAppConnector `yaml:",inline"`
}

type Outputs struct {
	IsValidated       bool
	ValidationMessage string
}
