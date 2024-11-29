package constants

const (
	VersionLatest          = "latest"
	SemanticVersionDefault = "1.1.1"
)

const (
	UserDefinedCredentialsPath = "credentials"
	UserDefinedApplicationPath = "applications"
)

const (
	YAMLTypeSrc       = "src.yaml"
	YAMLTypeGenerated = "generated.yaml"
)

const (
	DeclarativesDataTypeSTRING = "STRING"
	DeclarativesDataTypeINT    = "INT"
	DeclarativesDataTypeFLOAT  = "FLOAT"
	DeclarativesDataTypeFILE   = "FILE"
)

const (
	DeclarativesDataTypeInferSTRING = "string"
	DeclarativesDataTypeInferINT    = "int"
	DeclarativesDataTypeInferFLOAT  = "float64"
	DeclarativesDataTypeInferFILE   = "[]byte"
)

const (
	VersionDefault = "latest"
)

const ApplicationStruct = `package {{PACKAGE_NAME}}

{{IMPORT_PACKAGES}}
import (
    "fmt"
    "strings"
    {{LINKED_APPLICATIONS_IMPORTS}}
)

{{USER_DEFINED_CREDENTIAL_STRUCT_VO}}

type UserDefinedCredentials struct{
    {{USER_DEFINED_CREDENTIALS}}
}

type LinkedApplications struct{
    {{LINKED_APPLICATIONS}}
}

type {{APPLICATION_STRUCT_NAME}}  struct{
	AppURL string ` + "`" + `json:"appURL" yaml:"appURL"` + "`" + `
	AppPort int ` + "`" + `json:"appPort" yaml:"appPort"` + "`" + `
	Ipv4Address string ` + "`" + `json:"ipv4Address" yaml:"ipv4Address"` + "`" + `
	Ipv6Address string ` + "`" + `json:"ipv6Address" yaml:"ipv6Address"` + "`" + `
	UserDefinedCredentials *UserDefinedCredentials ` + "`" + `json:"userDefinedCredentials" yaml:"userDefinedCredentials"` + "`" + `
    LinkedApplications *LinkedApplications ` + "`" + `json:"linkedApplications" yaml:"linkedApplications"` + "`" + `

}

func (thisObj *{{APPLICATION_STRUCT_NAME}}) Validate() (bool,error) {
	return true,nil
}
{{VALIDATE_ATTRIBUTES}}
// INFO : You can implement your own implementation for the class

`

// {{APPLICATION_PACKAGE_NAME}} "appconnections/{{APPLICATION_PACKAGE_NAME}}/{{VERSION}}"

const ValidateTaskStruct = `// This file is autogenerated. Modify as per your task needs.
package main

import (
	{{APPLICATION_PACKAGE_NAME}} "appconnections/{{APPLICATION_PACKAGE_NAME}}"
)

type UserInputs struct {
	{{APPLICATION_PACKAGE_NAME}}.{{APP_STRUCT_NAME}} ` + "`yaml:\",inline\"`" + `
}

type Outputs struct {
	IsValidated       bool
    ValidationMessage string
}

`

const ValidateTask = `// This file is autogenerated. Modify as per your task needs.

package main

// {{TASK_NAME}} :
func (inst *TaskInstance) {{TASK_NAME}}(inputs *UserInputs, outputs *Outputs) (err error) {

	outputs.IsValidated, err = inputs.Validate()
    if err != nil {
		outputs.ValidationMessage = err.Error()
	} else {
		outputs.ValidationMessage = "Credentials validated successfully"
	}

	return nil
}

`

// replace appconnections => ../../../

const ValidateTaskGoModLibraryPointers = `

require appconnections v0.0.0-00010101000000-000000000000

replace cowlibrary => ../../../../../src/cowlibrary


replace appconnections => ../../

`

const TaskGoModLibraryPointers = `

require appconnections v0.0.0-00010101000000-000000000000

replace cowlibrary => ../../../../src/cowlibrary

replace appconnections => ../../../appconnections/go

`

const PyStructHelper = `class {{CLASS_NAME}}:
{{SELF_PARAM_DECLARATION}}

	def __init__(self,{{INIT_PARAM}}) -> None: 
{{INIT_HELPER_METHODS}}

	@staticmethod
	def from_dict(obj) -> '{{CLASS_NAME}}':
		{{PARAM_DECLARATION}} = {{PARAM_VALUE_DECLARATION}}
		if isinstance(obj, dict):
{{FROM_DICT_HANDLE}}

		return {{CLASS_NAME}}({{PARAM_DECLARATION}})

	def to_dict(self) -> dict:
		result: dict = {}
{{TO_DICT_HANDLE}}
		return result
`

const LinkedAppClassSelfParam = `linked_applications: LinkedApplications`
const LinkedAppInitParam = `, linked_applications: LinkedApplications = None`
const LinkedAppInitSelfParam = `self.linked_applications = linked_applications`
const LinkedAppToDictResultValue = `result["LinkedApplications"] = self.linked_applications.to_dict()`
const LinkedAppFromDictResultValue = `
            linked_applications_dict = obj.get("LinkedApplications",None)
            if linked_applications_dict is None:
                linked_applications_dict=obj.get("linkedApplications",None)
            if bool(linked_applications_dict):
               linked_applications = LinkedApplications.from_dict(linked_applications_dict)
`
const LinkedAppStaticMethodVariable = `linked_applications = None`
const ApplicationStaticMethodReturnValues = `(app_url, app_port, user_defined_credentials)`
const ApplicationStaticMethodReturnValuesWithLinkedApp = `(app_url, app_port, user_defined_credentials, linked_applications)`

const ApplicationStruct_Py = `from typing import List, Any, Dict
{{LINKED_APPLICATIONS_IMPORTS}}
{{USER_DEFINED_CREDENTIAL_STRUCT_VO}}
{{VALIDATE_METHODS}}

{{LINKED_APPLICATION_CLASS}}

class UserDefinedCredentials:
{{SELF_PARAM_DECLARATION}}

	def __init__(self,{{INIT_PARAM}}) -> None:
{{INIT_HELPER_METHODS}}

	@staticmethod
	def from_dict(obj) -> 'UserDefinedCredentials':
		{{PARAM_DECLARATION}} = {{PARAM_VALUE_DECLARATION}}
		if isinstance(obj, dict):
{{FROM_DICT_HANDLE}}
		return UserDefinedCredentials({{PARAM_DECLARATION}})

	def to_dict(self) -> dict:
		result: dict = {}
{{TO_DICT_HANDLE}}
		return result


class {{APPLICATION_STRUCT_NAME}}:
    app_url: str
    app_port: int
    user_defined_credentials: UserDefinedCredentials
    {{LINKED_APP_CLASS_SELF_PARAM}}
   
    def __init__(self, app_url: str = None, app_port: int = None, user_defined_credentials: UserDefinedCredentials = None{{LINKED_APP_INIT_PARAM}}) -> None:
        self.app_url = app_url
        self.app_port = app_port
        self.user_defined_credentials = user_defined_credentials
        {{LINKED_APP_INIT_SELF_PARAM}}


    @staticmethod
    def from_dict(obj) -> '{{APPLICATION_STRUCT_NAME}}':
        app_url, app_port, user_defined_credentials = "", "", None
        {{LINKED_APP_STATIC_VARIABLE_DECLARE}}
        if isinstance(obj, dict):
            app_url = obj.get("AppURL","")
            if not app_url:
                app_url = obj.get("appURL","")
            if not app_url:
                app_url = obj.get("appurl","")
            app_port = obj.get("AppPort",0)
            if not app_port:
                app_port = obj.get("appPort",0)
            user_defined_credentials_dict = obj.get("UserDefinedCredentials",None)
            if user_defined_credentials_dict is None:
                user_defined_credentials_dict=obj.get("userDefinedCredentials",None)
            if bool(user_defined_credentials_dict):
                user_defined_credentials = UserDefinedCredentials.from_dict(user_defined_credentials_dict)

{{LINKED_APP_FROM_DICT}}
    
        return {{APPLICATION_STRUCT_NAME}}{{APPLICATION_STATIC_METHOD_RETURN_VALUES}}

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result["UserDefinedCredentials"] = self.user_defined_credentials.to_dict()
        {{LINKED_APP_TO_DICT_RESULT}}
        return result

    def validate(self) -> bool and dict:
        # PLACE-HOLDER
        return True, None

	# INFO : You can implement methods (to access the application) which can be then invoked from your task code

`

const ValidateTask_Py = `# This file is autogenerated. Modify as per your task needs.

from pathlib import Path
import sys

path_root = Path(__file__).parents[1]
sys.path.append(str(path_root))

import {{APPLICATION_PACKAGE_NAME}}

from typing import overload
from compliancecowcards.structs import cards, cowvo
import json

class {{TASK_NAME}}(cards.AbstractTask):

    def execute(self) -> dict:
        user_defined_credentials = None
        if self.task_inputs and self.task_inputs.user_inputs:
            user_defined_credentials = self.task_inputs.user_inputs

        {{APPLICATION_PACKAGE_NAME}}_obj = {{APPLICATION_PACKAGE_NAME}}.{{APP_CLASS_NAME}}.from_dict(user_defined_credentials)

        is_valid, validation_message = {{APPLICATION_PACKAGE_NAME}}_obj.validate()
		
        if validation_message and not isinstance(validation_message, str):
            validation_message = json.dumps(validation_message)

        response = {
            "IsValidated": is_valid,
            "ValidationMessage": "Credentials Validated Successfully" if is_valid else validation_message
        }

        return response

`

const ApplicationYAML = `# This file is autogenerated. Modify as per your task needs.

apiVersion: v1alpha1
kind: applicationClass
meta:
  name: {{APPLICATION_CLASS_NAME}} # only alpha
  displayName: {{APPLICATION_CLASS_NAME}} # Display name
  labels: # required. The rule orchestrator selects the INSTANCE of the APPLICATION CLASS based on the labels described here
    appType: [{{APPLICATION_CLASS_TAG}}]
  annotations: # optional. These are user defined labels for reporting purposes
    annotateType: [{{APPLICATION_CLASS_TAG}}]
  version: {{APPLICATION_VERSION}} # semver
spec:
  url: http://localhost.com # string
  hasSupportForCURLValidation: false # If you want to enable the curl support in CC UI, mark this as 'true'
  port: # port
  credentialTypes:
{{CREDENTIAL_TYPES}}
  defaultCredentialType: # optional. If not explicitly specified, the default credential type is the first one selected for the given application class
  directAccess: true # optional. default = true. Specifies if the application class is directly accessible from ComplianceCow
{{LINKED_APPLICATION_CLASSES_YAML}}
  # linkableApplicationClasses: # optional. List of SUPPORTED application classes that are linkable. Only classes successfully resolved here, shall be shown in the drop down in the Linked Applications for an instance of this application class
  # - name: LinkableApplicationName # optional
  management: false # optional. default = false. Specifies if the application class is a management class. For example, an image repository can be an application class that can enumerate every single container image in it. In such cases, the repository application class will have management = true
  # allowableChildrenApplicationClasses:
  # - name: ChildAllowedValues # optional
  type: user  # optional. default = user. Specifies category of the application class such as user | system | action | remediation
`

const LinkedApplicationClassYaml = `
  linkableApplicationClasses:
{{LINKED_APPLICATION_NAMES}}
`
