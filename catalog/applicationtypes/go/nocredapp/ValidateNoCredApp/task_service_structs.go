// This file is autogenerated. Modify as per your task needs.
package main

import (
	nocredapp "applicationtypes/nocredapp"
)

type UserInputs struct {
	nocredapp.NoCredApp `yaml:",inline"`
}

type Outputs struct {
	IsValidated       bool
	ValidationMessage string
}

