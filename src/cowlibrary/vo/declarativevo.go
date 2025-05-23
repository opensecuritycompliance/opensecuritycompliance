package vo

type Meta struct {
	Name        string              `yaml:"name" json:"name" binding:"required,rulename,lte=120" validate:"required,rulename,lte=120"`
	Purpose     string              `yaml:"purpose,omitempty" json:"purpose,omitempty"`
	Description string              `yaml:"description,omitempty" json:"description,omitempty"`
	Icon        string              `json:"icon,omitempty" yaml:"icon,omitempty"`
	AliasRef    string              `yaml:"alias,omitempty"  json:"aliasRef,omitempty" binding:"omitempty,alphanum" validate:"omitempty,alphanum"`
	Type        string              `yaml:"type,omitempty" json:"type,omitempty"`
	App         string              `yaml:"app,omitempty" json:"app,omitempty" binding:"omitempty,alpha" validate:"omitempty,alpha"`
	Labels      map[string][]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Annotations map[string][]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
}

type MetaDataTemplate struct {
	RuleGUID          string
	RuleTaskGUID      string
	ControlID         string
	PlanExecutionGUID string
}

type YamlBase struct {
	APIVersion string `json:"apiVersion" yaml:"apiVersion" binding:"required,oneof='rule.policycow.live/v1alpha1'" validate:"required,oneof='rule.policycow.live/v1alpha1'"`
	Kind       string `json:"kind" yaml:"kind" binding:"required,oneof='rule' 'ruleGroup' 'rulegroup' 'ruleRun' 'ruleGroupRun' 'applicationScope'" validate:"required,oneof='rule' 'ruleGroup' 'rulegroup' 'ruleRun' 'ruleGroupRun' 'applicationScope'"`
}
type BaseAndMeta struct {
	YamlBase `yaml:",inline"`
	Meta     *Meta `json:"meta" yaml:"meta"`
}

// used with apply command
type YamlRuleVO struct {
	BaseAndMeta `yaml:",inline"`
	Spec        struct {
		DetailedInputs []*DetailedInput `yaml:"inputs" binding:"required,dive,omitempty" validate:"required,dive,omitempty"`
		Tasks          []*TaskVO        `yaml:"tasks" binding:"required,dive,omitempty" validate:"required,dive,omitempty"`
		Refmaps        []string         `yaml:"ioMap" binding:"required,dive" validate:"required,dive"`
	} `yaml:"spec"`
	Status interface{} `yaml:"status"`
}

// Used with init command
type RuleYAMLVO struct {
	BaseAndMeta `yaml:",inline"`
	Spec        *RuleYAMLSpecVO `json:"spec" yaml:"spec" binding:"required" validate:"required"`
	Catalog     string          `json:"catalog,omitempty" yaml:"catalog,omitempty"`
	RuleStatus  string          `json:"ruleStatus,omitempty" yaml:"ruleStatus,omitempty"`
}

type RuleYAMLSpecVO struct {
	Input         map[string]interface{} `json:"inputs,omitempty" yaml:"inputs,omitempty"`
	UserInputs    []*RuleUserInputVO     `json:"userInputs,omitempty" yaml:"userInputs,omitempty" binding:"omitempty,dive" validate:"omitempty,dive"`
	InputsMeta__  []*RuleUserInputVO     `json:"inputsMeta__,omitempty" yaml:"inputsMeta__,omitempty" binding:"omitempty,dive"  validate:"omitempty,dive"`
	OutputsMeta__ []*RuleUserInputVO     `json:"outputsMeta__,omitempty" yaml:"outputsMeta__,omitempty" binding:"omitempty,dive"  validate:"omitempty,dive"`
	Tasks         []*TaskVO              `json:"tasks" yaml:"tasks" binding:"required" validate:"required,dive"`
	IoMap         []string               `json:"ioMap" yaml:"ioMap" binding:"required" validate:"required"`
}

type ApplicationClassVO struct {
	Name                    string      `yaml:"name"`
	AppURL                  string      `yaml:"appURL"`
	Port                    int         `yaml:"appPort,omitempty"`
	UserDefinedCredentialVO interface{} `yaml:"userDefinedCredentials"`
}

type YamlBaseVO struct {
	BaseAndMeta `yaml:",inline"`
	Spec        interface{} `yaml:"spec"`
}

type YamlRuleGroupVO struct {
	BaseAndMeta `yaml:",inline"`
	Spec        struct {
		Rules   []*RuleInfo `json:"rulesInfo" yaml:"rules" binding:"required,dive" validate:"required,dive"`
		Refmaps []string    `json:"refMap" yaml:"ioMap"`
	} `yaml:"spec"`
}

type RuleRunYaml struct {
	BaseAndMeta `yaml:",inline"`
	Spec        struct {
		Inputs           map[string]interface{} `yaml:"inputs" binding:"required" validate:"required"`
		ApplicationScope string                 `yaml:"applicationScope" binding:"required" validate:"required"`
		SystemScope      string                 `yaml:"systemScope" binding:"required" validate:"required"`
	} `yaml:"spec"`
	Status Status `yaml:"status,omitempty"`
}
type Status struct {
	Status interface{}
}

type RuleGroupRunYaml struct {
	BaseAndMeta `yaml:",inline"`
	Spec        struct {
		Rules []struct {
			Name             string `yaml:"name,omitempty" binding:"required" validate:"required"`
			ApplicationScope string `yaml:"applicationScope" binding:"required" validate:"required"`
			SystemScope      string `yaml:"systemScope" binding:"required" validate:"required"`
		} `yaml:"rules"`
		ApplicationScope string `yaml:"applicationScope"`
		SystemScope      string `yaml:"systemScope"`
	} `yaml:"spec"`
}

type RuleGroupYAMLVO struct {
	BaseAndMeta `yaml:",inline"`
	Spec        struct {
		Input       map[string]interface{} `yaml:"inputs,omitempty" binding:"required,dive,omitempty" validate:"required,dive,omitempty"`
		RulesInfo   []*RuleInfo            `json:"rulesInfo,omitempty" yaml:"rules,omitempty" binding:"required,dive,omitempty" validate:"required,dive,omitempty"`
		IoMap       []string               `yaml:"ioMap" binding:"required,dive" validate:"required,dive"`
		Synthesizer *SynthesizeVO          `json:"synthesizer,omitempty" yaml:"synthesizer,omitempty"`
	} `yaml:"spec"`
}

type RuleUserInputVO struct {
	Name          string        `json:"name,omitempty" yaml:"name,omitempty"`
	Description   string        `json:"description,omitempty" yaml:"description,omitempty"`
	DataType      string        `json:"dataType" yaml:"dataType,omitempty" binding:"required,oneof='STRING' 'INT' 'BOOLEAN' 'FLOAT' 'FILE' 'JSON' 'HTTP_CONFIG'" validate:"required,oneof='STRING' 'INT' 'FLOAT' 'FILE' 'JSON' 'BOOLEAN' 'HTTP_CONFIG'"`
	Repeated      bool          `json:"repeated" yaml:"repeated"`
	Format        string        `json:"format,omitempty" yaml:"format,omitempty" binding:"omitempty,oneof='csv' 'parquet' 'ndjson' 'json' 'xlsx' 'yaml' 'har' 'toml' 'rego' 'xml'" validate:"omitempty,oneof='csv' 'parquet' 'ndjson' 'json' 'xlsx' 'yaml' 'har' 'toml' 'rego' 'xml'"`
	DefaultValue  interface{}   `json:"defaultValue,omitempty" yaml:"defaultValue,omitempty" binding:"required" validate:"required"`
	AllowedValues []interface{} `json:"allowedValues" yaml:"allowedValues"`
	ShowField     bool          `json:"showField,omitempty" yaml:"showField,omitempty"`
	Required      bool          `json:"required,omitempty" yaml:"required,omitempty"`
}

type RuleUserInputVOV2 struct {
	Name          string        `json:"name,omitempty" yaml:"name,omitempty"`
	DataType      string        `json:"dataType" yaml:"dataType,omitempty" binding:"required,oneof='STRING' 'INT' 'FLOAT' 'FILE' 'JSON' 'HTTP_CONFIG'" validate:"required,oneof='STRING' 'INT' 'FLOAT' 'FILE' 'JSON' 'HTTP_CONFIG'"`
	Repeated      bool          `json:"repeated" yaml:"repeated"`
	Format        string        `json:"format,omitempty" yaml:"format,omitempty"`
	DefaultValue  interface{}   `json:"defaultValue,omitempty" yaml:"defaultValue,omitempty"`
	AllowedValues []interface{} `json:"allowedValues" yaml:"allowedValues"`
	ShowField     bool          `json:"showField,omitempty" yaml:"showField,omitempty"`
	Required      bool          `json:"required,omitempty" yaml:"required,omitempty"`
}
