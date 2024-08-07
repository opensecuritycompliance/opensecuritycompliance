package vo

import (
	"encoding/base64"
	"fmt"

	"gopkg.in/yaml.v3"
)

type CowApplicationErrorLevel string

const (
	CowApplicationErrorLevel_UNDEFINED_ERROR CowApplicationErrorLevel = "UNDEFINED_ERROR"
	CowApplicationErrorLevel_INFO            CowApplicationErrorLevel = "INFO"
	CowApplicationErrorLevel_WARN            CowApplicationErrorLevel = "WARN"
	CowApplicationErrorLevel_CRITICAL        CowApplicationErrorLevel = "CRITICAL"
)

type AttributeDataType string

const (
	AttributeDataType_STRING AttributeDataType = "STRING"
	AttributeDataType_INT    AttributeDataType = "INT"
	AttributeDataType_FLOAT  AttributeDataType = "FLOAT"
	AttributeDataType_FILE   AttributeDataType = "BYTES"
)

type CredentialSpecVO struct {
	Extends    []*CredentialsPointerVO   `json:"extends,omitempty" yaml:"extends,omitempty" binding:"omitempty" validate:"omitempty"` //dive,nameandversion
	Attributes []*CredentialAttributesVO `json:"attributes" binding:"required,dive" validate:"required,dive"`
}

type CredentialAttributesVO struct {
	Name          string            `json:"name,omitempty" yaml:"name" binding:"alpha" validate:"alpha"`
	DisplayName   string            `json:"displayName,omitempty" yaml:"displayName" binding:"omitempty,name" validate:"omitempty,name"`
	Secret        bool              `json:"secret,omitempty" yaml:"secret" `
	Required      bool              `json:"required,omitempty" yaml:"required"`
	MultiSelect   bool              `json:"multiSelect,omitempty" yaml:"multiSelect"`
	DataType      AttributeDataType `json:"dataType,omitempty" yaml:"dataType" binding:"required" validate:"required"`
	AllowedValues []string          `json:"allowedValues,omitempty" yaml:"allowedValues" binding:"omitempty" validate:"omitempty"` // dive,name,unique
	DefaultValue  string            `json:"defaultValue,omitempty" yaml:"defaultValue" binding:"omitempty" validate:"omitempty"`
}

type CowDeclarativeVO struct {
	ID         string `json:"id" yaml:"id"`
	APIVersion string `json:"apiVersion" yaml:"apiVersion" binding:"required,eq=v1alpha1" validate:"required,eq=v1alpha1"`
	Kind       string `json:"kind" yaml:"kind" binding:"required,oneof=credentialType applicationClass" validate:"required,oneof=credentialType applicationClass"`
}

type CowMetaVO struct {
	Name             string              `json:"name" yaml:"name" binding:"required,alpha" validate:"required,alpha"`
	DisplayName      string              `json:"displayName" yaml:"displayName" binding:"omitempty,name" validate:"omitempty,name"`
	ShortDescription string              `json:"shortDescription" yaml:"shortDescription" binding:"omitempty,name" validate:"omitempty,name"`
	LongDescription  string              `json:"longDescription" yaml:"longDescription" binding:"omitempty,name" validate:"omitempty,name"`
	Labels           map[string][]string `json:"labels" yaml:"labels"`
	Annotations      map[string][]string `json:"annotations" yaml:"annotations"`
	Version          string              `json:"version,omitempty" yaml:"version,omitempty" binding:"omitempty,semver" validate:"omitempty,semver"`
}

type UserDefinedCredentialVO struct {
	CowDeclarativeVO      `yaml:",inline"`
	Meta                  *CowMetaVO        `json:"meta" yaml:"meta" binding:"required" validate:"required"`
	Spec                  *CredentialSpecVO `json:"spec" yaml:"spec" binding:"required" validate:"required"`
	Status                *StatusVO         `json:"status" yaml:"status"`
	IsVersionToBeOverride bool              `json:"isVersionToBeOverride" yaml:"isVersionToBeOverride"`
}

type StatusVO struct {
	ValidationErrors []*CowApplicationErrorsVO `json:"errors,omitempty"  yaml:"errors"`
}

type CowApplicationErrorsVO struct {
	Code        int    `json:"code,omitempty" yaml:"code"`
	Description string `json:"description,omitempty" yaml:"description"`
	// Level       CowApplicationErrorLevel `json:"level,omitempty" yaml:"level"`
}

type CowSelectorVO struct {
	AnyOf           map[string][]string `json:"anyOf,omitempty" yaml:"anyOf"`
	AllOf           map[string][]string `json:"allOf,omitempty" yaml:"allOf"`
	NoneOf          map[string][]string `json:"noneOf,omitempty" yaml:"noneOf"`
	MatchExpression struct {
		Sql   string `json:"sql,omitempty" yaml:"sql"`
		GOCel string `json:"gocel,omitempty" yaml:"gocel"`
	} `json:"matchExpression,omitempty" yaml:"matchExpression"`
}

type CowNamePointersVO struct {
	Name       string                    `json:"name" yaml:"name" binding:"alpha" validate:"alpha"`
	Version    string                    `json:"version,omitempty" yaml:"version,omitempty" binding:"omitempty,semver" validate:"omitempty,semver"`
	AppDetails *UserDefinedApplicationVO `json:"appDetails,omitempty" yaml:"appDetails,omitempty" binding:"omitempty" validate:"omitempty"`
}

type CredentialsPointerVO struct {
	CowNamePointersVO `yaml:",inline"`
	Repeated          bool `json:"repeated" yaml:"repeated"`
}

type CowApplicationSpecVO struct {
	URL                                 string                  `json:"url" yaml:"url" binding:"required,url" validate:"required,url"`
	Ipv4Address                         string                  `json:"ipv4Address"  yaml:"ipv4Address" binding:"omitempty,ipv4" validate:"omitempty,ipv4"`
	Ipv6Address                         string                  `json:"ipv6Address"  yaml:"ipv6Address" binding:"omitempty,ipv6" validate:"omitempty,ipv6"`
	Port                                int                     `json:"port" yaml:"port" binding:"omitempty,lt=64000" validate:"omitempty,lt=64000"`
	Validation                          ApplicationValidationVO `json:"validation"  yaml:"validation"`
	CredentialTypes                     []*CredentialsPointerVO `json:"credentialTypes"  yaml:"credentialTypes" binding:"required,dive" validate:"required,dive"`
	Selectors                           *CowSelectorVO          `json:"selectors" yaml:"selectors" binding:"omitempty,dive" validate:"omitempty,dive"`
	DefaultCredentialType               *CowNamePointersVO      `json:"defaultCredentialType,omitempty" yaml:"defaultCredentialType,omitempty"`
	ApplicationType                     string                  `json:"applicationType" yaml:"applicationType" binding:"omitempty,oneof=system user" validate:"omitempty,oneof=system user"`
	DirectAccess                        bool                    `json:"directAccess" yaml:"directAccess"`
	LinkableApplicationClasses          []*CowNamePointersVO    `json:"linkableApplicationClasses,omitempty" yaml:"linkableApplicationClasses" binding:"omitempty,dive" validate:"omitempty,dive"`
	Management                          bool                    `json:"management" yaml:"management"`
	AllowableChildrenApplicationClasses []*CowNamePointersVO    `json:"allowableChildrenApplicationClasses" yaml:"allowableChildrenApplicationClasses" binding:"omitempty,dive"  validate:"omitempty,dive"`
	Type                                string                  `json:"type" yaml:"type" binding:"omitempty,name" validate:"omitempty,name"`
	ExpectedSystemApplicationClasses    []*CowNamePointersVO    `json:"expectedSystemApplicationClasses" yaml:"expectedSystemApplicationClasses" binding:"omitempty,dive" validate:"omitempty,dive"`
}

type ApplicationValidationVO struct {
	TaskName    string `json:"taskName" yaml:"taskName" binding:"omitempty,name" validate:"omitempty,name"`
	TaskVersion string `json:"taskVersion" yaml:"taskVersion" binding:"omitempty,semver" validate:"omitempty,semver"`
}

type UserDefinedApplicationVO struct {
	CowDeclarativeVO      `yaml:",inline"`
	Meta                  *CowMetaVO            `json:"meta" yaml:"meta" binding:"required" validate:"required"`
	Spec                  *CowApplicationSpecVO `json:"spec" yaml:"spec" binding:"required" validate:"required"`
	Status                *StatusVO             `json:"status,omitempty" yaml:"status,omitempty"`
	IsVersionToBeOverride bool                  `json:"isVersionToBeOverride,omitempty" yaml:"isVersionToBeOverride,omitempty"`
	Language              string                `yaml:"language,omitempty"`
}

func (dt *AttributeDataType) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var yamlData interface{}
	if err := unmarshal(&yamlData); err != nil {
		return err
	}

	// Perform the mapping from YAML value to the custom type
	switch value := yamlData.(type) {
	case string:
		switch value {
		case "STRING":
			*dt = "string"
		case "INT":
			*dt = "int"
		case "FLOAT":
			*dt = "float64"
		case "FILE":
			*dt = "Bytes"
		default:
			return fmt.Errorf("unsupported data type: %s", value)
		}
	default:
		return fmt.Errorf("invalid data type: %v", value)
	}

	return nil
}

func (dt AttributeDataType) MarshalYAML() (interface{}, error) {
	var yamlValue string

	switch string(dt) {
	case "string":
		yamlValue = "STRING"
	case "int":
		yamlValue = "INT"
	case "float64":
		yamlValue = "FLOAT"
	case "Bytes":
		yamlValue = "FILE"
	default:
		yamlValue = "UNKNOWN"
	}

	return yamlValue, nil
}

type CowCredentialConfigurationCriteriaVO struct {
	Name                  string               `json:"name,omitempty" form:"name,omitempty"`
	Version               string               `json:"version,omitempty" form:"version,omitempty"`
	IsStatusToBeIncluded  bool                 `json:"isStatusToBeIncluded,omitempty" form:"isStatusToBeIncluded,omitempty"`
	Matcher               []*CowNamePointersVO `json:"matcher,omitempty" form:"matcher,omitempty"`
	CowCredentialConfigID string               `json:"cowCredentialConfigID" yaml:"cowCredentialConfigID"`
	State                 string               `json:"state" yaml:"state" form:"state"`
	CreatedBy             string               `json:"createdBy" yaml:"createdBy" form:"createdBy"`
}

type CowResponseVO struct {
	ID string `json:"id" yaml:"id" form:"id"`
}

type CowTaskVO struct {
	CNAPIVersion  string `json:"cnAPIVersion"`
	CNTaskName    string `json:"cnTaskName"`
	CNTaskPurpose string `json:"cnTaskPurpose"`
	CNTaskAlias   string `json:"cnTaskAlias"`
	CNTaskUser    struct {
		Domain struct {
			CNCustomerFQDN string `json:"cnCustomerFQDN"`
			CNOrgUnit      string `json:"cnOrgUnit"`
			CNGroupID      string `json:"cnGroupID"`
		} `json:"Domain"`
		UserID string `json:"UserID"`
	} `json:"cnTaskUser"`
	CNTaskVersion struct {
		UserVersion   string `json:"UserVersion"`
		SystemVersion string `json:"SystemVersion"`
	} `json:"cnTaskVersion"`
	DomianLevelAccess bool `json:"domianLevelAccess,omitempty"`
}

type CowTaskTagsUpdateVO struct {
	Tags struct {
		WorkernodeType []string `json:"workernodetype"`
		Type           []string `json:"type__"`
	} `json:"tags"`
	CNInputStrings []struct {
		CNKey   string `json:"cnKey"`
		CNValue string `json:"cnValue"`
	} `json:"cnInputStrings"`
}

type CowTaskResponseVO struct {
	TaskGUID string `json:"TaskGUID"`
}

type Bytes []byte

func (b Bytes) MarshalYAML() (interface{}, error) {
	return base64.StdEncoding.EncodeToString(b), nil
}

func (b *Bytes) UnmarshalYAML(node *yaml.Node) error {
	value := node.Value
	ba, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	*b = ba
	return nil
}

type PolicyCowDataSet struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Path        string `json:"path,omitempty"`
	Folder      string `json:"folder,omitempty"`
}

type ApplicationValidatorVO struct {
	ApplicationType  string                 `json:"applicationType,omitempty" yaml:"applicationType,omitempty" validate:"required,alpha" binding:"required,alpha"`
	CredentialType   string                 `json:"credentialType,omitempty" yaml:"credentialType,omitempty" validate:"required,alpha" binding:"required,alpha"`
	CredentialValues map[string]interface{} `json:"credentialValues,omitempty" yaml:"credentialValues,omitempty" validate:"required" binding:"required"`
	Language         string                 `json:"language,omitempty" yaml:"language,omitempty" validate:"required,oneof='go' 'python'" binding:"required,oneof='go' 'python'"`
	ApplicationURL   string                 `json:"appURL,omitempty" yaml:"appURL,omitempty" validate:"required" binding:"required"`
}

type ApplicationValidatorRespVO struct {
	Valid   bool   `json:"valid" yaml:"valid"`
	Message string `json:"message,omitempty" yaml:"message,omitempty"`
}

type ApplicationVO struct {
	AuthConfigVO
	Name     string `json:"name,omitempty" validate:"required,alpha" binding:"required,alpha"`
	Language string `json:"language,omitempty" validate:"oneof='go' 'python'" binding:"omitempty,oneof='go' 'python'"`
}

type ApplicationValidationResult struct {
	AppName       string           `json:"appName"`
	Valid         *bool            `json:"valid,omitempty"`
	Message       string           `json:"message,omitempty"`
	ErrorResponse *ErrorResponseVO `json:",omitempty"`
}

type LinkedAppsCredentials struct {
	ApplicationName    string                   `json:"appName,omitempty" yaml:"name" binding:"required" validate:"required"`
	CredentialValues   map[string]interface{}   `json:"credentialValues,omitempty" yaml:"credentialValues,omitempty"`
	CredentialType     string                   `json:"credentialType,omitempty" yaml:"credentialType,omitempty"`
	ApplicationURL     string                   `json:"appURL,omitempty" yaml:"appURL,omitempty" binding:"required"`
	LinkedApplications []*LinkedAppsCredentials `json:"linkedApps,omitempty" yaml:"linkedApps,omitempty"`
}
