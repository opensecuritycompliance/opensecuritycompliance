package vo

import (
	"time"
)

type RuleSet struct {
	Id                string          `json:"id,omitempty"`
	Rules             []*Rule         `json:"rules,omitempty"`
	Hash              string          `json:"hash,omitempty"`
	Type              string          `json:"type,omitempty"`
	Applicationscope  interface{}     `json:"applicationScope,omitempty"`
	AppGroupGUID      string          `json:"appGroupGUID,omitempty"`
	PlanExecutionGUID string          `json:"planExecutionGUID,omitempty"`
	ControlID         string          `json:"controlID,omitempty"`
	FromDate          time.Time       `json:"fromDate,omitempty"`
	ToDate            time.Time       `json:"toDate,omitempty"`
	AdditionalInfo    *AdditionalInfo `json:"additionalInfo,omitempty"`
}

type RuleBase struct {
	RuleGUID      string `json:"ruleGUID,omitempty"`
	RuleName      string `json:"rulename,omitempty"`
	Purpose       string `json:"purpose,omitempty"`
	Description   string `json:"description,omitempty"`
	AliasRef      string `json:"aliasref,omitempty"`
	SeqNo         int    `json:"seqno,omitempty"`
	InstanceName  string `json:"instanceName,omitempty"`
	ObjectType    string `json:"objectType,omitempty"`
	ObjectGUID    string `json:"objectGUID,omitempty"`
	RuleType      string `json:"ruletype,omitempty"`
	CoreHash      string `json:"coreHash,omitempty"`
	ExtendedHash  string `json:"extendedHash,omitempty"`
	State         int    `json:"-"`
	CompliancePCT int    `json:"compliancePCT,omitempty"`
}

type GeneralVO struct {
	DomainID string `json:"domainId,omitempty"`
	OrgID    string `json:"orgId,omitempty"`
	GroupID  string `json:"groupId,omitempty"`
}

type Rule struct {
	RuleBase `yaml:",inline"`
	GeneralVO
	Id                string    `json:"id,omitempty"`
	ParentId          string    `json:"parentId,omitempty"`
	RootId            string    `json:"rootId,omitempty"`
	Type              string    `json:"type,omitempty"`
	AppGroupGUID      string    `json:"appGroupGUID,omitempty"`
	PlanExecutionGUID string    `json:"planExecutionGUID,omitempty"`
	ControlID         string    `json:"controlID,omitempty"`
	ControlType       string    `json:"controlType,omitempty"`
	FromDate          time.Time `json:"fromDate,omitempty"`
	ToDate            time.Time `json:"toDate,omitempty"`
	FailThresholdPCT  int       `json:"failThresholdPCT,omitempty"`

	TasksInfo      []interface{}       `json:"tasksinfo,omitempty"`
	RuleIOValues   *IOValues           `json:"ruleiovalues,omitempty"`
	RefMaps        []*RefStruct        `json:"refmaps,omitempty"`
	RuleTags       map[string][]string `json:"ruleTags,omitempty"`
	RuleExceptions []string            `json:"-"`
	MapOfMaps      map[string]string   `json:"-"`
	Evidences      []*Evidence         `json:"evidences"`
}

type TaskBase struct {
	TaskGUID    string              `json:"taskguid,omitempty"`
	AliasRef    string              `json:"aliasref,omitempty"`
	Purpose     string              `json:"purpose,omitempty"`
	Description string              `json:"description,omitempty"`
	TaskState   int                 `json:"-"`
	Type        string              `json:"type,omitempty"`
	SeqNo       int                 `json:"seqno,omitempty"`
	AppTags     map[string][]string `json:"appTags,omitempty"`
}

type TaskInfo struct {
	TaskBase
	Id                string    `json:"id,omitempty"`
	AppGroupGUID      string    `json:"appGroupGUID,omitempty"`
	PlanExecutionGUID string    `json:"planExecutionGUID,omitempty"`
	ControlID         string    `json:"controlID,omitempty"`
	RuleID            string    `json:"ruleID,omitempty"`
	ObjectType        string    `json:"objectType,omitempty"`
	ObjectGUID        string    `json:"objectGUID,omitempty"`
	FromDate          time.Time `json:"fromDate,omitempty"`
	ToDate            time.Time `json:"toDate,omitempty"`
	FailThresholdPCT  int       `json:"failThresholdPCT,omitempty"`
	TaskIOValues      *IOValues `json:"taskiovalues,omitempty"`
	TaskException     error     `json:"taskexception,omitempty"`
}

type RefStruct struct {
	TargetRef FieldMap `json:"targetref,omitempty"`
	SourceRef FieldMap `json:"sourceref,omitempty"`
}

type FieldMap struct {
	FieldType string `json:"fieldtype,omitempty"`
	AliasRef  string `json:"aliasref,omitempty"`
	TaskGUID  string `json:"taskguid,omitempty"`
	VarName   string `json:"varname,omitempty"`
}

type RuleInfo struct {
	RuleName   string                 `json:"name,omitempty" yaml:"name,omitempty" binding:"required,alphanum" validate:"required,alphanum"`
	AliasRef   string                 `json:"alias,omitempty" yaml:"alias,omitempty" binding:"required,alphanum" validate:"required,alphanum"`
	DependsOn  []string               `json:"dependsOn,omitempty" yaml:"dependsOn,omitempty"`
	UserInputs map[string]interface{} `json:"userInputs,omitempty" yaml:"userInputs,omitempty"`
}

type RuleDependency struct {
	RuleGroup   string        `json:"ruleGroup,omitempty"`
	RulesInfo   []*RuleInfo   `json:"rulesInfo,omitempty" binding:"required,dive" validate:"required,dive"`
	RefMap      []*RefStruct  `json:"refMap,omitempty"`
	Inputs      *UserInputsVO `json:"inputs,omitempty"`
	Synthesizer *SynthesizeVO `json:"synthesizer,omitempty"`
}

type SynthesizeVO struct {
	SynthesizerInfo   []*SynthesizerInfo `json:"synthesizerInfo,omitempty"`
	SynthesizerRefMap []*RefStruct       `json:"synthesizerRefMap,omitempty"`
}

type IOValues struct {
	Inputs          map[string]interface{} `json:"inputs,omitempty"`
	InputsMeta__    []*RuleUserInputVO     `json:"inputsMeta__,omitempty"`
	OutputsMeta__   []*RuleUserInputVO     `json:"outputsMeta__,omitempty"`
	Outputs         map[string]interface{} `json:"outputs,omitempty"`
	Facts           map[string]interface{} `json:"facts,omitempty"`
	OutputFiles     map[string]string      `json:"outputFiles,omitempty"`
	DetailedInputs  []*DetailedInput       `json:"inputs_,omitempty"`
	DetailedOutputs map[string]interface{} `json:"outputs_,omitempty"`
	ProcessFiles    []string               `json:"processFiles,omitempty"`
	TempFiles       []string               `json:"tempFiles,omitempty"`
}

type RuleSetOutput struct {
	State            string        `json:"state,omitempty"`
	ComplianceStatus string        `json:"complianceStatus,omitempty"`
	CompliancePCT    int           `json:"compliancePCT,omitempty"`
	Type             string        `json:"type,omitempty"`
	RuleOutputs      []*RuleOutput `json:"ruleOutputs,omitempty"`
}

type RuleOutput struct {
	OutputType         string         `json:"outputType,omitempty"`
	Type               string         `json:"type,omitempty"`
	Purpose            string         `json:"purpose,omitempty"`
	Description        string         `json:"description,omitempty"`
	AliasRef           string         `json:"aliasref,omitempty"`
	SeqNo              int            `json:"seqno,omitempty"`
	InstanceName       string         `json:"instanceName,omitempty"`
	ObjectType         string         `json:"objectType,omitempty"`
	ObjectGUID         string         `json:"objectGUID,omitempty"`
	State              string         `json:"state,omitempty"`
	ComplianceStatus   string         `json:"complianceStatus,omitempty"`
	CompliancePCT      int            `json:"compliancePCT,omitempty"`
	TaskState          map[string]int `json:"taskState,omitempty"`
	RuleIOValues       *IOValues      `json:"ruleiovalues,omitempty"`
	RuleOutputs        []*RuleOutput  `json:"ruleOutputs,omitempty"`
	OutputFieldRemarks string         `json:"outputFieldRemarks,omitempty"`
}

type TaskDetails struct {
	RuleJSONPath string
	SrcTaskName  string
	TaskPath     string
}

type TaskFlow struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec TaskSpec `yaml:"spec"`
}

type TaskSpec struct {
	MethodCatalogFilePath string            `yaml:"methodCatalogFilePath"`
	RulePath              string            `yaml:"rulePath"`
	TaskInputs            []PolicyCowIOInfo `yaml:"taskInputs"`
	TaskOutputs           []PolicyCowIOInfo `yaml:"taskOutputs"`
	Language              string            `yaml:"language,omitempty"`
	Methods               []struct {
		Label  string `yaml:"label"`
		Name   string `yaml:"name,omitempty"`
		Inputs struct {
			Object []interface{} `yaml:"[object Object]"`
		} `yaml:"inputs,omitempty"`
	} `yaml:"methods"`
}
type Method struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		MethodCatalogFilePath string   `yaml:"methodCatalogFilePath"`
		MethodCall            string   `yaml:"methodCall"`
		MethodCode            string   `yaml:"methodCode"`
		Imports               []string `yaml:"imports"`
		Outputs               []string `yaml:"outputs"`
	} `yaml:"spec"`
}

type TaskInputVO struct {
	TaskName             string
	Alias                string
	Description          string
	Language             string
	RefMaps              []*RefStruct `json:"refmaps,omitempty"`
	IsSQLRule            bool
	SupportFilesToCreate []*SupportedFilesVO
	ValidationCURL       string
	TaskToBeCreated      bool
	Comments             TaskCommentsVO
}

type UserData struct {
	Credentials struct {
		Compliancecow struct {
			ClientID     string `json:"clientId" yaml:"clientId"`
			ClientSecret string `json:"clientSecret" yaml:"clientSecret"`
			SubDomain    string `json:"subDomain" yaml:"subDomain"`
		} `json:"compliancecow" yaml:"compliancecow"`
	} `json:"credentials" yaml:"credentials"`
}

type UserInputs struct {
	Credentials          []*CredentialVO `description:"Application Credentials"`
	IsCredentialValidate bool
	IsFetchDataType      bool
	IsFetchDataBasic     bool
	IsFetchDataAll       bool
}

type RuleOutputs struct {
	Id                     string                 `json:"id,omitempty"`
	RuleName               string                 `json:"ruleName,omitempty"`
	AliasRef               string                 `json:"aliasref,omitempty"`
	Outputs                map[string]interface{} `json:"outputs,omitempty"`
	RuleGroup              string                 `json:"ruleGroup,omitempty"`
	Evidences              []*Evidence            `json:"evidences,omitempty"`
	MissingOutputVariables []string               `json:"-"`
}

type RuleGroupVO struct {
	Name string `json:"name,omitempty"`
}

type RuleVO struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}
type TaskVO struct {
	Name           string              `json:"name,omitempty" yaml:"name" binding:"required,taskname" validate:"required,taskname"`
	Alias          string              `json:"aliasref,omitempty" yaml:"alias" binding:"required" validate:"required"`
	Type           string              `json:"type,omitempty" yaml:"type"`
	AppTags        map[string][]string `json:"appTags,omitempty" yaml:"appTags,omitempty"`
	ValidationCURL string              `json:"validationCURL,omitempty" yaml:"validationCURL,omitempty"`
	TaskGUID       string              `json:"taskguid,omitempty" yaml:"taskguid,omitempty"`
	Catalog        string              `json:"catalog,omitempty" yaml:"catalog,omitempty"`
	Purpose        string              `json:"Purpose,omitempty" yaml:"purpose"`
	Description    string              `json:"description,omitempty" yaml:"description"`
	TaskToBeCreate bool                `json:"taskToBeCreate,omitempty" yaml:"taskToBeCreate,omitempty"`
	TemplateFile   string              `json:"templateFile,omitempty" yaml:"templateFile,omitempty"`
	Evidences      []*CowEvidenceVO    `json:"evidences,omitempty" yaml:"evidences,omitempty"`
	Language       string              `json:"language,omitempty" yaml:"language,omitempty" binding:"omitempty,oneof=python go" validate:"omitempty,oneof=python go"`
	AlreadyExists  bool                `json:"alreadyExists,omitempty" yaml:"already_exist,omitempty"`
	Application    *CowApplicationVO   `json:"application,omitempty" yaml:"application,omitempty"`
	Comments       TaskCommentsVO      `json:"comments,omitempty" yaml:"comments,omitempty"`
}

type TaskCommentsVO struct {
	Code string `json:"code,omitempty" yaml:"code,omitempty"`
	Task string `json:"task,omitempty" yaml:"task,omitempty"`
}

type RuleInputVO struct {
	RuleName   string        `json:"ruleName,omitempty"`
	RuleMap    string        `json:"ruleMap,omitempty"`
	FileInputs *FileInputsVO `json:"fileInputs,omitempty"`
}

type FileInputsVO struct {
	SystemObjectsValue    []*ObjectTemplate      `yaml:"systemObject" json:"systemObjectsValue,omitempty"`
	TaskInputValue        map[string]interface{} `yaml:"input" json:"taskInputValue,omitempty"`
	UserObjectAppValue    *ObjectTemplate        `yaml:"userObject" json:"UserObjectAppValue,omitempty"`
	UserObjectServerValue *ObjectTemplate        `json:"userObjectServerValue,omitempty"`
}
type TaskInput struct {
	SystemInputs `yaml:",inline"`
	UserInputs   map[string]interface{} `yaml:"userInputs"`
}
type SystemInputs struct {
	UserObject    *UserObjectTemplate `yaml:"userObject"`
	SystemObjects []*ObjectTemplate   `yaml:"systemObjects,omitempty"`
	MetaData      *MetaDataTemplate   `yaml:"metaData,omitempty"`
	FromDate_     time.Time           `yaml:"fromDate,omitempty"`
	ToDate_       time.Time           `yaml:"toDate,omitempty"`
}

type SystemInputsV2 struct {
	UserObject    *UserObjectTemplate `yaml:"userObject"`
	SystemObjects []*ObjectTemplate   `yaml:"systemObjects,omitempty"`
	MetaData      *MetaDataTemplate   `yaml:"metaData,omitempty"`
}

type TaskInputV2 struct {
	SystemInputsV2 `yaml:",inline"`
	UserInputs     map[string]interface{} `yaml:"userInputs"`
	FromDate_      string                 `yaml:"fromDate"`
	ToDate_        string                 `yaml:"toDate"`
}

type UserInputsVO struct {
	UserInputs map[string]interface{} `yaml:"userInputs"`
	FromDate_  string                 `yaml:"fromDate"`
	ToDate_    string                 `yaml:"toDate"`
}

type UserObjectTemplate struct {
	ObjectTemplate         `yaml:",inline"`
	Name                   string              `yaml:"name,omitempty"`
	AppURL                 string              `yaml:"appURL,omitempty"`
	AppTags                map[string][]string `json:"appTags,omitempty" yaml:"appTags,omitempty"`
	Port                   int                 `yaml:"appPort,omitempty"`
	UserDefinedCredentials interface{}         `yaml:"userDefinedCredentials,omitempty"`
}

type ObjectTemplate struct {
	App         *AppAbstract    `yaml:"app,omitempty"`
	Apps        []*AppAbstract  `yaml:"apps,omitempty"`
	Server      *ServerAbstract `yaml:"server,omitempty"`
	Credentials []*Credential   `yaml:"credentials,omitempty"`
}

type ServerBase struct {
	ServerGUID      string
	ServerName      string `json:"servername,omitempty"`
	ApplicationGUID string `json:"appid,omitempty"`
	ServerType      string `json:"servertype,omitempty"`
	ServerURL       string `json:"serverurl,omitempty"`
	ServerHostName  string `json:"serverhostname,omitempty"`
}

type ServerAbstract struct {
	ServerBase
	ID            string              `json:"id,omitempty"`
	ServerTags    map[string][]string `json:"servertags,omitempty"`
	ServerBootSeq int                 `json:"serverbootseq,omitempty"`
	ActionType    string              `json:"actiontype,omitempty"`
	OSInfo        struct {
		OSDistribution string `json:"osdistribution,omitempty"`
		OSKernelLevel  string `json:"oskernellevel,omitempty"`
		OSPatchLevel   string `json:"ospatchlevel,omitempty"`
	} `json:"osinfo,omitempty"`
	IPv4Addresses map[string]string `json:"ipv4addresses,omitempty"`
	Volumes       map[string]string `json:"volumes,omitempty"`
	OtherInfo     struct {
		CPU      int `json:"cpu,omitempty"`
		GBMemory int `json:"memory_gb,omitempty"`
	} `json:"otherinfo,omitempty"`
	ClusterInfo struct {
		ClusterName    string            `json:"clustername,omitempty"`
		ClusterMembers []*ServerAbstract `json:"clustermembers,omitempty"`
	} `json:"clusterinfo,omitempty"`
	Servers               []*ServerAbstract      `json:"servers,omitempty"`
	SystemObjectsValue    []*ObjectTemplate      `json:"systemObjectsValue,omitempty"`
	TaskInputValue        map[string]interface{} `json:"taskInputValue,omitempty"`
	UserObjectAppValue    *ObjectTemplate        `json:"UserObjectAppValue,omitempty"`
	UserObjectServerValue *ObjectTemplate        `json:"userObjectServerValue,omitempty"`
}

type TaskOutputs struct {
	Outputs *Outputs
}

type Outputs struct {
	Credentials []*CredentialVO `description:"Application Credential output"`
	Error       string
	InputLen    int
}

type ExecuteRuleVO struct {
	RuleInputs      *TaskInputVO `json:"ruleInputs,omitempty" yaml:"ruleInputs,omitempty"`
	RuleName        string       `json:"ruleName,omitempty" yaml:"ruleName,omitempty"`
	InGlobalCatalog bool         `json:"inGlobalCatalog,omitempty" yaml:"inGlobalCatalog,omitempty"`
	UpsertRule      bool         `json:"upsertRule,omitempty" yaml:"upsertRule,omitempty"`
}

type ExecuteRuleRespVO struct {
	TaskInputs *TaskInputVO `json:"taskInputs,omitempty" yaml:"taskInputs,omitempty"`
}

type RuleIOMapInfo struct {
	InputVaribales  []string
	OutputVaribales []string
}

type RuleAdditionalInfo struct {
	TaskInfos     []*TaskInputVO
	RuleIOMapInfo *RuleIOMapInfo
}

type RuleExecutionVO struct {
	RuleName           string                   `json:"ruleName,omitempty" yaml:"ruleName,omitempty" binding:"required"`
	RuleInputs         []*RuleUserInputVO       `json:"ruleInputs,omitempty" yaml:"ruleInputs,omitempty"`
	CredentialValues   map[string]interface{}   `json:"credentialValues,omitempty" yaml:"credentialValues,omitempty"`
	CredentialType     string                   `json:"credentialType,omitempty" yaml:"credentialType,omitempty"`
	ApplicationURL     string                   `json:"appURL,omitempty" yaml:"appURL,omitempty"`
	RuleInputMap       map[string]interface{}   `json:"ruleInputMap,omitempty" yaml:"ruleInputMap,omitempty"`
	Applications       []*ApplicationCredVO     `json:"applications,omitempty" yaml:"applications,omitempty"`
	LinkedApplications []*LinkedAppsCredentials `json:"linkedApps,omitempty" yaml:"linkedApps,omitempty"`
	FromDate           string                   `json:"fromDate,omitempty" yaml:"fromDate,omitempty"`
	ToDate             string                   `json:"toDate,omitempty" yaml:"toDate,omitempty"`
}

type RuleProgressVO struct {
	OutputVO
	RuleName            string               `json:"ruleName,omitempty" yaml:"ruleName,omitempty"`
	Progress            []*TaskProgressVO    `json:"progress,omitempty" yaml:"progress,omitempty"`
	ErrorDetails        interface{}          `json:"errorDetails,omitempty" yaml:"errorDetails,omitempty"`
	TaskProgressSummary *TaskProgressSummary `json:"taskProgressSummary,omitempty" yaml:"taskProgressSummary,omitempty"`
}

type TaskProgressSummary struct {
	Total              int     `json:"total,omitempty"`
	Completed          int     `json:"completed,omitempty"`
	InProgress         int     `json:"inProgress,omitempty"`
	Error              int     `json:"error,omitempty"`
	ProgressPercentage float64 `json:"progressPercentage,omitempty"`
}

type OutputVO struct {
	Status        string                 `json:"status,omitempty" yaml:"status,omitempty"`
	Outputs       map[string]interface{} `json:"outputs,omitempty" yaml:"outputs,omitempty"`
	Inputs        map[string]interface{} `json:"inputs,omitempty" yaml:"inputs,omitempty"`
	Errors        map[string]interface{} `json:"errors,omitempty" yaml:"errors,omitempty"`
	StartDateTime time.Time              `json:"startDateTime,omitempty" yaml:"startDateTime,omitempty"`
	EndDateTime   time.Time              `json:"endDateTime,omitempty" yaml:"endDateTime,omitempty"`
	Duration      time.Duration          `json:"duration,omitempty" yaml:"duration,omitempty"`
}

type TaskProgressVO struct {
	OutputVO
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
}

type RuleExecutionProgressVO struct {
	ExecutionID string `json:"executionID,omitempty" yaml:"executionID,omitempty" binding:"required,uuid"`
}

type AuthConfigVO struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	SubDomain    string `json:"subDomain"`
	Host         string `json:"host"`
	UserDomain   string `json:"userDomain"`
}
type PublishRuleVO struct {
	AuthConfigVO
	RuleName    string `json:"ruleName"`
	CanOverride bool   `json:"canOverride"`
	CCRuleName  string `json:"ccRuleName"`
}

type DomainDetailVO struct {
	ClientID   string `json:"clientId"`
	DomainName string `json:"domainName"`
}

type LogEntry struct {
	CreatedTime string            `json:"createdTime"`
	Payload     map[string]string `json:"payload"`
}

type TaskLog struct {
	TaskName string     `json:"taskName"`
	Logs     []LogEntry `json:"logs"`
}

type RuleLogData struct {
	RuleName        string    `json:"ruleName"`
	ApplicationName string    `json:"applicationName"`
	Tasks           []TaskLog `json:"tasks"`
}

type DeleteRuleVO struct {
	RuleNames   []string `json:"ruleNames"`
	IgnoreError bool     `json:"ignoreError"`
}

type DesignNotesVO struct {
	RuleName           string `json:"ruleName,omitempty" validate:"required"`
	DesignNotesContent string `json:"designNotesContent,omitempty"`
	Type               string `json:"type,omitempty" validate:"oneof=mcp MCP"`
}

type DesignNotesResponseVO struct {
	FileName           string `json:"fileName,omitempty"`
	DesignNotesContent string `json:"designNotesContent,omitempty"`
}

type RuleEntry struct {
	Name    string `yaml:"name"`
	Catalog string `yaml:"catalog"`
}
type RuleListSpec struct {
	RuleOverrideEnabled            bool        `yaml:"ruleOverrideEnabled"`
	PublishApplicationTypeEnabled  bool        `yaml:"publishApplicationTypeEnabled"`
	ApplicationTypeLanguage        string      `yaml:"applicationTypeLanguage,omitempty"`
	ApplicationTypeOverrideEnabled bool        `yaml:"applicationTypeOverrideEnabled,omitempty"`
	Rules                          []RuleEntry `yaml:"rules"`
}
type RuleListMetadata struct {
	Name    string `yaml:"name"`
	Purpose string `yaml:"purpose"`
}
type RuleListYAML struct {
	Kind     string           `yaml:"kind"`
	Metadata RuleListMetadata `yaml:"metadata"`
	Spec     RuleListSpec     `yaml:"spec"`
}
