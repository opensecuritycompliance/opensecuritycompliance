// This file is autogenerated. Modify as per your task needs.
package main

import (
	salesforceappconnector "applicationtypes/salesforceappconnector"
)

type UserInputs struct {
	salesforceappconnector.SalesforceAppConnector `yaml:",inline"`
}

type Outputs struct {
	IsValidated       bool
    ValidationMessage string
}

