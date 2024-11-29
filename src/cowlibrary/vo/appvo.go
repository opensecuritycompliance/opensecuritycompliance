package vo

type Credential struct {
	CredentialBase `yaml:",inline"`
	ID             string                 `json:"id,omitempty"  yaml:"id,omitempty"`
	PasswordHash   []byte                 `json:"passwordhash,omitempty"  yaml:"passwordhash,omitempty"`
	Password       string                 `json:"passwordstring,omitempty" yaml:"password,omitempty"`
	LoginURL       string                 `json:"loginurl,omitempty" yaml:"loginURL,omitempty" binding:"required,url" validate:"required,url"`
	SSHPrivateKey  []byte                 `json:"sshprivatekey,omitempty" yaml:"sshprivatekey,omitempty"`
	CredTags       map[string][]string    `json:"credtags,omitempty" yaml:"tags,omitempty"`
	OtherCredInfo  map[string]interface{} `json:"othercredinfomap" yaml:"otherCredentials" binding:"required" validate:"required"`
}

type CredentialBase struct {
	CredGUID   string `json:"credguid,omitempty"  yaml:"credguid,omitempty"`
	CredType   string `json:"credtype" yaml:"credType" binding:"required" validate:"required"`
	SourceGUID string `json:"sourceguid,omitempty"  yaml:"sourceguid,omitempty"`
	SourceType string `json:"sourcetype,omitempty"  yaml:"sourcetype,omitempty"`
	UserID     string `json:"userID,omitempty"  yaml:"userid,omitempty"`
}

type CredentialVO struct {
	ID                    string                 `json:"id,omitempty" yaml:"id,omitempty"`
	CredentialType        string                 `json:"credentialType,omitempty" yaml:"credentialType,omitempty"`
	CredentialName        string                 `json:"credentialName,omitempty" yaml:"credentialName,omitempty"`
	AppType               string                 `json:"appType,omitempty" yaml:"appType,omitempty"`
	AppURL                string                 `json:"appURL,omitempty" yaml:"appURL,omitempty"`
	AppHost               string                 `json:"appHost,omitempty" yaml:"appHost,omitempty"`
	AppPort               int                    `json:"appPort,omitempty" yaml:"appPort,omitempty"`
	OthersTags            map[string][]string    `json:"othersTags,omitempty" yaml:"othersTags,omitempty"`
	Credential            map[string]interface{} `json:"credential,omitempty" yaml:"credential,omitempty"`
	Status                string                 `json:"status,omitempty" yaml:"status,omitempty"`
	IsValidated           bool                   `json:"isValidated,omitempty" yaml:"isValidated,omitempty"`
	ErrorMessage          string                 `json:"errorMessage,omitempty" yaml:"errorMessage,omitempty"`
	Data                  []byte                 `json:"data,omitempty" yaml:"data,omitempty"`
	DataType              []string               `json:"dataType,omitempty" yaml:"dataType,omitempty"`
	ReferencedCredentials []*CredentialVO        `json:"referencedCredentials,omitempty" yaml:"referencedCredentials,omitempty"`
}

type AppAbstract struct {
	AppBase                `yaml:",inline"`
	ID                     string                    `json:"id,omitempty" yaml:"id,omitempty"`
	AppSequence            int                       `json:"appSequence,omitempty" yaml:"appsequence,omitempty"`
	AppTags                map[string][]string       `json:"appTags,omitempty"  yaml:"appTags,omitempty" binding:"required" validate:"required"`
	ActionType             string                    `json:"actionType,omitempty"  yaml:"actiontype,omitempty"`
	AppObjects             map[string]interface{}    `yaml:"appobjects,omitempty"`
	Servers                []*ServerAbstract         `json:"servers,omitempty" yaml:"servers,omitempty"`
	UserDefinedCredentials interface{}               `json:"userDefinedCredentials,omitempty" yaml:"userDefinedCredentials,omitempty"`
	LinkedApplications     map[string][]*AppAbstract `yaml:"linkedApplications,omitempty"`
}

type AppBase struct {
	ApplicationName string                 `json:"appName,omitempty" yaml:"name" binding:"required" validate:"required"`
	ApplicationGUID string                 `json:"applicationguid,omitempty" yaml:"applicationguid,omitempty"`
	AppGroupGUID    string                 `json:"appgroupguid,omitempty" yaml:"appgroupguid,omitempty"`
	ApplicationURL  string                 `json:"appURL,omitempty" yaml:"appURL,omitempty"`
	ApplicationPort string                 `yaml:"appPort,omitempty"`
	OtherInfo       map[string]interface{} `yaml:"otherinfo,omitempty"`
}

type ApplicationScopeVO struct {
	BaseAndMeta `yaml:",inline"`
	Spec        *ObjectTemplate   `yaml:"spec"`
	Status      []*AppScopeStatus `yaml:"status,omitempty"`
}
type AppScopeStatus struct {
	ApplicationName string `yaml:"app,omitempty"`
	CredentialName  string `yaml:"credentialName,omitempty"`
	IsValidated     bool   `yaml:"isValidated,omitempty"`
	ErrorMessage    string `yaml:"errorMessage,omitempty"`
}
type SystemScopeVO struct {
	BaseAndMeta `yaml:",inline"`
	Spec        []*ObjectTemplate `yaml:"spec"`
	Status      []*AppScopeStatus `yaml:"status,omitempty"`
}
