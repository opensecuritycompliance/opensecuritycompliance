package vo

type CowRuleMetaVO struct {
	Name        string `json:"name,omitempty" yaml:"name,omitempty" binding:"required" validate:"required"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

type CowApplicationVO struct {
	Name               string `json:"name,omitempty" yaml:"name,omitempty"`
	Type               string `json:"type,omitempty" yaml:"type,omitempty" binding:"required" validate:"required"`
	AlreadyExists      bool   `json:"alreadyExists,omitempty" yaml:"already_exist,omitempty"`
	URL                string `json:"url,omitempty" yaml:"url,omitempty"`
	ValidationCURL     string `json:"validationCURL,omitempty" yaml:"validationCURL,omitempty"`
	Level              string `json:"level,omitempty" yaml:"level,omitempty"`
	CredentailType     string `json:"credentailType,omitempty" yaml:"credentailType,omitempty"`
	PrimaryApplication bool   `json:"primaryApplication,omitempty" yaml:"primary_application,omitempty"`
}

type CowRuleSpecVO struct {
	Application  *CowApplicationVO      `json:"application,omitempty" yaml:"application,omitempty" binding:"required" validate:"required"`
	Inputs       map[string]interface{} `json:"inputs,omitempty" yaml:"inputs,omitempty"`
	Outputs      map[string]interface{} `json:"outputs,omitempty" yaml:"outputs,omitempty"`
	InputsMeta__ []*RuleUserInputVO     `json:"inputsMeta__,omitempty" yaml:"inputsMeta__,omitempty"`
	UserInputs   []*RuleUserInputVO     `json:"userInputs,omitempty" yaml:"userInputs,omitempty" binding:"omitempty,dive" validate:"omitempty,dive"`
	Tasks        []*TaskVO              `json:"tasks,omitempty" yaml:"tasks,omitempty" binding:"required,dive,omitempty" validate:"required,dive,omitempty"`
	IOMap        []string               `json:"ioMap,omitempty" yaml:"ioMap,omitempty"`
}

type CowEvidenceVO struct {
	Name         string `json:"name,omitempty" yaml:"name,omitempty" binding:"required" validate:"required"`
	Weight       int    `json:"weight,omitempty" yaml:"weight,omitempty"`
	TemplateFile any    `json:"templateFile,omitempty" yaml:"template_file,omitempty"`
	Comments     any    `json:"comments,omitempty" yaml:"comments,omitempty"`
}

type LLMRuleInfoVO struct {
	YamlBase `yaml:",inline"`
	Meta     *CowRuleMetaVO `json:"meta" yaml:"meta" binding:"required" validate:"required"`
	Spec     *CowRuleSpecVO `json:"spec" yaml:"spec" binding:"required" validate:"required"`
}
