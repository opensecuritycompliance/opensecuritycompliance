// This file is autogenerated. Modify as per your task needs.
package main

import (
	servicenowconnector "applicationtypes/servicenowconnector"
)

type UserInputs struct {
	servicenowconnector.ServiceNowConnector `yaml:",inline"`
}

type Outputs struct {
	IsValidated       bool
	ValidationMessage string
}
