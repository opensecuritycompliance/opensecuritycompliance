// This file is autogenerated. Modify as per your task needs.
package main

import (
	kubernetes "applicationtypes/kubernetes"
)

type UserInputs struct {
	kubernetes.Kubernetes `yaml:",inline"`
}

type Outputs struct {
	IsValidated       bool
	ValidationMessage string
}
