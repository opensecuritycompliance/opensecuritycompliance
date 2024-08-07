package vo

type Meta struct {
	Name        string              `yaml:"name" json:"name" binding:"required,rulename,lte=120" validate:"required,rulename,lte=120"`
	Purpose     string              `yaml:"purpose,omitempty" json:"purpose,omitempty"`
	Description string              `yaml:"description,omitempty" json:"description,omitempty"`
	AliasRef    string              `yaml:"alias,omitempty"  json:"aliasRef,omitempty" binding:"omitempty,alphanum" validate:"omitempty,alphanum"`
	Type        string              `yaml:"type,omitempty" json:"type,omitempty"`
	App         string              `yaml:"app,omitempty" json:"app,omitempty" binding:"required,alpha" validate:"required,alpha"`
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
	APIVersion string `yaml:"apiVersion" binding:"required,oneof='rule.policycow.live/v1alpha1'" validate:"required,oneof='rule.policycow.live/v1alpha1'"`
	Kind       string `yaml:"kind" binding:"required,oneof='rule' 'ruleGroup' 'rulegroup' 'ruleRun' 'ruleGroupRun' 'applicationScope'" validate:"required,oneof='rule' 'ruleGroup' 'rulegroup' 'ruleRun' 'ruleGroupRun' 'applicationScope'"`
}
type BaseAndMeta struct {
	YamlBase `yaml:",inline"`
	Meta     *Meta `yaml:"meta"`
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
	Spec        *RuleYAMLSpecVO `yaml:"spec" binding:"required" validate:"required"`
}

type RuleYAMLSpecVO struct {
	Input        map[string]interface{} `yaml:"inputs,omitempty"`
	UserInputs   []*RuleUserInputVO     `yaml:"userInputs,omitempty" binding:"omitempty,dive" validate:"omitempty,dive"`
	InputsMeta__ []*RuleUserInputVO     `yaml:"inputsMeta__,omitempty" binding:"omitempty,dive"  validate:"omitempty,dive"`
	Tasks        []*TaskVO              `yaml:"tasks" binding:"required" validate:"required,dive"`
	IoMap        []string               `yaml:"ioMap" binding:"required" validate:"required"`
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
	Type   string      `json:"type" yaml:"type,omitempty" binding:"required,oneof='STRING' 'INT' 'FLOAT' 'FILE' 'JSON'" validate:"required,oneof='STRING' 'INT' 'FLOAT' 'FILE' 'JSON'"`
	Format string      `json:"format" yaml:"format,omitempty" binding:"omitempty,oneof='csv' 'parquet' 'ndjson' 'json' 'xlsx'" validate:"omitempty,oneof='csv' 'parquet' 'ndjson' 'json' 'xlsx'"`
	Name   string      `json:"name,omitempty" yaml:"name,omitempty"`
	Value  interface{} `json:"value,omitempty" yaml:"value,omitempty" binding:"required" validate:"required"`
}
