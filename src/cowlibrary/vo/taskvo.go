package vo

type PolicyCowTaskVO struct {
	Authors                  []string                 `json:"authors,omitempty" yaml:"authors,omitempty"`
	Domain                   string                   `json:"domain,omitempty" yaml:"domain,omitempty"`
	CreatedDate              string                   `json:"createdDate,omitempty" yaml:"createdDate,omitempty"`
	Name                     string                   `json:"name,omitempty" yaml:"name,omitempty"`
	DisplayName              string                   `json:"displayName,omitempty" yaml:"displayName,omitempty"`
	Purpose                  string                   `json:"purpose,omitempty" yaml:"purpose,omitempty"`
	Version                  string                   `json:"version,omitempty" yaml:"version,omitempty"`
	Description              string                   `json:"description,omitempty" yaml:"description,omitempty"`
	ShaToken                 string                   `json:"shaToken,omitempty" yaml:"shaToken,omitempty"`
	ShowInCatalog            bool                     `json:"showInCatalog,omitempty" yaml:"showInCatalog,omitempty"`
	Icon                     string                   `json:"icon,omitempty" yaml:"icon,omitempty"`
	Type                     string                   `json:"type,omitempty" yaml:"type,omitempty"`
	Tags                     []string                 `json:"tags,omitempty" yaml:"tags,omitempty"`
	ApplicationType          string                   `json:"applicationType,omitempty" yaml:"applicationType,omitempty"`
	UserObjectJSONInBase64   string                   `json:"userObjectJSONInBase64,omitempty" yaml:"userObjectJSONInBase64,omitempty"`
	SystemObjectJSONInBase64 string                   `json:"systemObjectJSONInBase64,omitempty" yaml:"systemObjectJSONInBase64,omitempty"`
	Inputs                   []*PolicyCowTaskInputVO  `json:"inputs,omitempty" yaml:"inputs,omitempty"`
	Outputs                  []*PolicyCowTaskOutputVO `json:"outputs,omitempty" yaml:"outputs,omitempty"`
	CatalogType              string                   `json:"catalogType,omitempty" yaml:"catalogType,omitempty"`
	AppTags                  map[string][]string      `json:"appTags,omitempty"  yaml:"appTags,omitempty"`
	ReadmeData               string                   `json:"readmeData,omitempty" yaml:"readmeData,omitempty"`
}

type PolicyCowTaskInputVO struct {
	Name            string        `json:"name,omitempty" yaml:"name,omitempty"`
	Description     string        `json:"description,omitempty" yaml:"description,omitempty"`
	DataType        string        `json:"dataType,omitempty" yaml:"dataType,omitempty"`
	Repeated        bool          `json:"repeated,omitempty" yaml:"repeated,omitempty"`
	DisplayName     string        `json:"displayName,omitempty" yaml:"displayName,omitempty"`
	AllowedValues   []interface{} `json:"allowedValues,omitempty" yaml:"allowedValues,omitempty"`
	DefaultValue    string        `json:"defaultValue,omitempty" yaml:"defaultValue,omitempty"`
	ShowField       bool          `json:"showField,omitempty" yaml:"showField,omitempty"`
	Required        bool          `json:"required,omitempty" yaml:"required,omitempty"`
	TemplateFile    string        `json:"templateFile,omitempty" yaml:"templateFile,omitempty"`
	Format          string        `json:"format,omitempty" yaml:"format,omitempty"`
	AllowUserValues bool          `json:"allowUserValues" yaml:"allowUserValues,omitempty"`
	Explanation     string        `json:"explanation" yaml:"explanation,omitempty"`
}

type PolicyCowTaskOutputVO struct {
	Name        string `json:"name,omitempty" yaml:"name,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	DataType    string `json:"dataType,omitempty" yaml:"dataType,omitempty"`
}
type CowTaskCriteriaVO struct {
	CriteriaVO
	Authors         []string `json:"authors,omitempty" in:"query=authors,authors[],Authors,Authors[]"`
	Domain          []string `json:"domain,omitempty" in:"query=domain,domain[],Domain,Domain[]"`
	CreatedDate     []string `json:"createdDate,omitempty" in:"query=created_date,created_date[],createdDate,createdDate[],CreatedDate,CreatedDate[]"`
	Name            []string `json:"name,omitempty" in:"query=name,name[],Name[],Name"`
	Version         []string `json:"version,omitempty" in:"query=version,version[],Version,Version[]"`
	Description     []string `json:"description,omitempty" in:"query=description,description[],Description,Description[]"`
	ShaToken        []string `json:"shaToken,omitempty" in:"query=sha_token,sha_token[],shaToken,shaToken[],ShaToken,ShaToken[]"`
	ShowInCatalog   bool     `json:"showInCatalog,omitempty" in:"query=show_in_catalog,showInCatalog,ShowInCatalog"`
	Type            []string `json:"type,omitempty" in:"query=type,Type,type[],Type[]"`
	Tags            []string `json:"tags,omitempty" in:"query=tags,Tags,tags[],Tags[]"`
	ApplicationType []string `json:"applicationType,omitempty" in:"query=application_type,application_type[],applicationType,applicationType[]"`
	ApplicationName []string `json:"applicationName,omitempty" in:"query=application_name,application_name[],applicationName,applicationName[]"`
}

type TaskExecutionVO struct {
	TaskName    string             `json:"taskName,omitempty" yaml:"taskName,omitempty" binding:"required"`
	Application *ApplicationCredVO `json:"application,omitempty" yaml:"application,omitempty"`
	TaskInputs  *TaskUserInputVO   `json:"taskInputs,omitempty" yaml:"taskInputs,omitempty"`
}

type TaskUpdateVO struct {
	TaskName  []string `json:"taskName,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Operation string   `json:"operation,omitempty"`
}
type TaskUserInputVO struct {
	Inputs map[string]interface{} `json:"inputs,omitempty" yaml:"inputs,omitempty" binding:"required" validate:"required"`
}

type TaskOutputsVO struct {
	Outputs map[string]interface{} `json:"Outputs,omitempty"`
	Error   string                 `json:"Error,omitempty"`
}
type TaskOutputResponse struct {
	TaskOutputs *TaskOutputsVO `json:"taskOutputs,omitempty"`
}

type RuleUpdateVO struct {
	RuleNames []string `json:"ruleNames,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Operation string   `json:"operation,omitempty"`
}

type UpsertReadMe struct {
	Type          string `json:"type,omitempty" yaml:"type,omitempty"`
	ReadmeContent string `json:"readmeContent,omitempty" yaml:"readmeContent,omitempty"`
	RuleName      string `json:"ruleName,omitempty" yaml:"ruleName,omitempty"`
}
