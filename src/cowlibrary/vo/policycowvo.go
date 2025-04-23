package vo

import (
	"time"

	"gopkg.in/yaml.v2"
)

type CodeCatalog struct {
	Method     string   `json:"method"`
	MethodCall string   `json:"methodCall"`
	Outputs    []string `json:"outputs,omitempty"`
	Imports    []string `json:"imports,omitempty"`
	MethodCode string   `json:"methodCode,omitempty"`
}
type PolicyCowFileInfo struct {
	FileByts []byte
	FilePath string
	FileName string
}

type PolicyCowIOInfo struct {
	Type        string `yaml:"type"`
	Name        string `yaml:"name"`
	Displayable string `yaml:"displayable"`
	Value       string `yaml:"value"`
}

type PolicyCowError struct {
	Type    string
	Name    string
	Message string
}

type SupportedFilesVO struct {
	FileName string
	FileData []byte
}

type PolicyCowConfig struct {
	Version           string                `json:"version" yaml:"version"`
	PathConfiguration *CowPathConfiguration `json:"pathConfiguration" yaml:"pathConfiguration"`
	UserData          *UserData             `json:"userData" yaml:"userData"`
}

type CowPathConfiguration struct {
	TasksPath            string `json:"tasksPath" yaml:"tasksPath"`
	RulesPath            string `json:"rulesPath" yaml:"rulesPath"`
	ExecutionPath        string `json:"executionPath" yaml:"executionPath"`
	RuleGroupPath        string `json:"ruleGroupPath" yaml:"ruleGroupPath"`
	SynthesizersPath     string `json:"synthesizersPath" yaml:"synthesizersPath"`
	DownloadsPath        string `json:"downloadsPath" yaml:"downloadsPath"`
	YamlFilesPath        string `json:"yamlFilesPath" yaml:"yamlFilesPath"`
	ApplicationScopePath string `json:"applicationScopePath" yaml:"applicationScopePath"`
	DashboardsPath       string `json:"dashboardsPath" yaml:"dashboardsPath"`
	LocalCatalogPath     string `json:"localCatalogPath" yaml:"localCatalogPath"`
	DeclarativePath      string `json:"declarativePath" yaml:"declarativePath"`
	AppConnectionPath    string `json:"appConnectionPath" yaml:"appConnectionPath"`
	ApplicationClassPath string `json:"applicationClassPath" yaml:"applicationClassPath"`
	CredentialsPath      string `json:"credentialsPath" yaml:"credentialsPath"`
}

type AdditionalInfo struct {
	PolicyCowConfig            *PolicyCowConfig         `json:"policyCowConfig,omitempty" yaml:"policyCowConfig"`
	Path                       string                   `json:"path" yaml:"path"`
	RuleName                   string                   `json:"ruleName" yaml:"ruleName"`
	RuleGroupName              string                   `json:"ruleGroupName" yaml:"ruleGroupName"`
	ExecutionID                string                   `json:"executionID" yaml:"executionID"`
	RuleExecutionID            string                   `json:"ruleExecutionID" yaml:"ruleExecutionID"`
	TaskExecutionID            string                   `json:"taskExecutionID" yaml:"taskExecutionID"`
	DownloadsPath              string                   `json:"downloadsPath" yaml:"downloadsPath"`
	TempDirPath                string                   `json:"tempDirPath" yaml:"tempDirPath"`
	ExportFileType             string                   `json:"exportFileType" yaml:"exportFileType"`
	IsTasksToBePrepare         bool                     `json:"isTasksToBePrepare" yaml:"isTasksToBePrepare"`
	SubDomain                  string                   `json:"subDomain" yaml:"subDomain"`
	Host                       string                   `json:"host" yaml:"host"`
	RulePublisher              *RulePublisher           `json:"rulePublisher"`
	DashboardVO                *DashboardVO             `json:"dashboardVO"`
	SynthesizerVO              *SynthesizerVO           `json:"synthesizerVO"`
	RuleDependency             *RuleDependency          `json:"ruleDependency,omitempty"`
	Rule                       *RuleSet                 `json:"rule,omitempty"`
	RuleInputVOs               []*RuleInputVO           `json:"ruleInputVOs,omitempty"`
	RuleInputs                 map[string]interface{}   `yaml:"inputs"`
	FileInputs                 *FileInputsVO            `json:"fileInputs,omitempty"`
	GlobalCatalog              bool                     `json:"globalCatalog,omitempty"`
	UpdateUserInputs           bool                     `json:"updateUserInputs,omitempty"`
	CanOverride                bool                     `json:"canOverride,omitempty"`
	AppCreateFlow              bool                     `json:"appCreateFlow,omitempty"`
	Language                   string                   `json:"language,omitempty"`
	ApplictionScopeConfigVO    *ApplictionScopeConfigVO `json:"applictionScopeConfigVO,omitempty"`
	PrimaryApplicationInfo     *ApplicationInfoVO       `json:"primaryApplicationInfo,omitempty"`
	ApplicationInfo            []*ApplicationInfoVO     `json:"applicationInfo,omitempty"`
	CredentialInfo             []CredentialItem         `json:"credentialInfo,omitempty"`
	PreserveRuleExecutionSetUp bool                     `json:"preserveRuleExecutionSetUp,omitempty"`
	ErrorOccured               bool                     `json:"errorOccured,omitempty"`
	RuleGUID                   string                   `json:"ruleGUID,omitempty"`
	ExecutionType              string                   `json:"executionType,omitempty"`
	RuleOutputVariableMap      map[string][]string      `json:"ruleOutputVariableMap,omitempty"`
	ValidationErrors           []string                 `json:"-"`
	ExecuteRuleVO              string                   `json:"executeRuleVO,omitempty"`
	RuleYAMLVO                 *RuleYAMLVO              `json:"ruleYAMLVO,omitempty"`
	RuleExecutionVO            *RuleExecutionVO         `json:"ruleExecutionVO,omitempty"`
	RuleProgressVO             *RuleProgressVO          `json:"ruleProgressVO,omitempty"`
	RuleOutputs                map[string]interface{}   `json:"-"`
	LinkedApplications         []LinkedApplicationVO    `json:"linkedApplications,omitempty"`
	SecurityContext            *SecurityContext         `json:"securityContext,omitempty"`
	InternalFlow               bool                     `json:"internalFlow,omitempty"`
	UserDomain                 string                   `json:"userDomain,omitempty"`
	RuleProgressWorker         *RuleProgressWorkerVO
	TerminateFlow              bool
	TaskVO                     *TaskVO
	ClientCredentials
}

type LinkedApplicationVO struct {
	Name   string
	Descr  string
	Path   string
	Global bool
}

type RuleProgressWorkerVO struct {
	RuleProgressChannel chan *RuleProgressVO
	Quit                bool
}

type CredentialItem struct {
	Name      string
	Version   string
	Directory string
}

type ApplicationInfoVO struct {
	App                *UserDefinedApplicationVO  `json:"app,omitempty"`
	Credential         []*UserDefinedCredentialVO `json:"credential,omitempty"`
	LinkedApplications []*ApplicationInfoVO       `json:"linkedApplications,omitempty"`
}

type ApplictionScopeConfigVO struct {
	FileData []byte `json:"fileData,omitempty"`
}

type CowRuleExecutions struct {
	ExecutionID   string                                       `json:"executionID,omitempty"`
	RuleGroupName string                                       `json:"ruleGroupName,omitempty"`
	RuleName      string                                       `json:"ruleName,omitempty"`
	RunDetails    map[string]map[string]map[string]interface{} `json:"runDetails,omitempty"`
	RuleOutputs   []*RuleOutputs                               `json:"ruleOutputs,omitempty"`
	CreatedAt     time.Time                                    `json:"createdAt,omitempty"`
	Type          string                                       `json:"type,omitempty"`
}

type ExportedData struct {
	FilePath string `json:"filePath"`
}

type Evidence struct {
	Name               string  `json:"name,omitempty"`
	Description        string  `json:"description,omitempty"`
	SynthesizerName    string  `json:"synthesizerName,omitempty"`
	DataFileHash       string  `json:"dataFileHash,omitempty"`
	MetaDataFileHash   string  `json:"metaDataFileHash,omitempty"`
	MetaDataFilePath   string  `json:"metaDataFilePath,omitempty"`
	MetaFieldFileHash  string  `json:"metaFieldFileHash,omitempty"`
	MetaFieldFilePath  string  `json:"metaFieldFilePath,omitempty"`
	DataFilePath       string  `json:"dataFilePath,omitempty"`
	FileName           string  `json:"fileName,omitempty"`
	Type               string  `json:"type,omitempty"`
	ComplianceStatus__ string  `json:"complianceStatus__,omitempty"`
	CompliancePCT__    float64 `json:"compliancePCT__,omitempty"`
	ComplianceWeight__ float64 `json:"complianceWeight__,omitempty"`
	ComplianceStatus   string  `json:"complianceStatus,omitempty"`
	CompliancePCT      float64 `json:"compliancePct,omitempty"`
	ComplianceWeight   float64 `json:"complianceWeight,omitempty"`
}

type ClientCredentials struct {
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	GrantType    string `json:"grant_type,omitempty"`
}

type AuthorizationResponse struct {
	TokenType string `json:"tokenType,omitempty"`
	AuthToken string `json:"authToken,omitempty"`
}

type RulePublisher struct {
	Data        []byte `json:"data,omitempty"`
	Name        string `json:"name,omitempty"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
}

type DetailedInput struct {
	Name              string            `json:"name" yaml:"name" binding:"required" validate:"required"`
	Display           string            `json:"display,omitempty" yaml:"displayName,omitempty"`
	Type              string            `json:"type,omitempty" yaml:"type,omitempty"`
	Mapper            string            `json:"mapper,omitempty"`
	IsMapper          bool              `json:"ismapper,omitempty"`
	IsResourcePattern bool              `json:"isresourcepattern,omitempty"`
	Template          string            `json:"template,omitempty"`
	IsRequired        bool              `json:"isrequired,omitempty"`
	ShowFieldInUI     bool              `json:"showfieldinui,omitempty" yaml:"showFieldInUI,omitempty" binding:"boolean" validate:"boolean"`
	Format            string            `json:"format,omitempty"`
	Value             string            `json:"value,omitempty"`
	DefaultValue      interface{}       `json:"defaultvalue,omitempty" yaml:"defaultValue,omitempty"`
	Description       string            `json:"description,omitempty"`
	OutputFiles       map[string]string `json:"outputFiles,omitempty"`
}

type RuleFlow struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		RulesFolderPath       string `yaml:"rulesFolderPath"`
		MethodCatalogFilePath string `yaml:"methodCatalogFilePath"`
		Rulename              string `yaml:"rulename"`
		Purpose               string `yaml:"purpose"`
		Description           string `yaml:"description"`
		Aliasref              string `yaml:"aliasref"`
		Ruleiovalues          struct {
			Inputs  []PolicyCowIOInfo `yaml:"inputs"`
			Outputs []PolicyCowIOInfo `yaml:"outputs"`
		} `yaml:"ruleiovalues"`
		Tasks []struct {
			TaskName         string   `yaml:"taskName,omitempty"`
			TaskAlias        string   `yaml:"taskAlias"`
			TaskFilePath     string   `yaml:"taskFilePath"`
			TaskYamlFilePath string   `yaml:"taskYamlFilePath,omitempty"`
			TaskSpec         TaskSpec `yaml:"taskSpec,omitempty"`
		} `yaml:"tasks"`
		Refmaps []string `yaml:"refmaps"`
	} `yaml:"spec"`
}

type Collection struct {
	Items      interface{} `json:"items"`
	TotalItems int         `json:"totalItems,omitempty"`
	TotalPage  int         `json:"totalPage,omitempty"`
	Page       int         `json:"page,omitempty"`
}

type CredentialYAML struct {
	UserDefinedCredentials map[string]map[string]interface{} `yaml:"userDefinedCredentials"`
}

type CredentialYAMLV2 struct {
	UserDefinedCredentials []yaml.MapItem `yaml:"userDefinedCredentials"`
}
