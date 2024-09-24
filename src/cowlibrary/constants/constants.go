package constants

import (
	"errors"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"cowlibrary/vo"
)

const (
	YAMLKindTypeTask        = "Task"
	YAMLKindTypeMethod      = "Method"
	YAMLKindTypeRule        = "Rule"
	YAMLKindTypeSQLRule     = "SQLRule"
	YAMLKindTypeCredential  = "credentialType"
	YAMLKindTypeApplication = "applicationClass"
)
const ApplicationScopeType = "UserObject"
const (
	ClassName            = "{{ClassName}}"
	ModuleName           = "{{ModuleName}}"
	FunctionName         = "{{FunctionName}}"
	PackageName          = "{{PackageName}}"
	MetaJsonFile         = "_meta.json"
	MarkDownFile         = "markdown.md"
	CowTemplateJinjaFile = "cow_template.jinja"
	CowDashBoardJSFile   = "cowdashboard.js"
)

var (
	COWAPIServiceProtocol = os.Getenv("COW_API_SERVICE_PROTOCOL")
	COWAPIServiceHostName = os.Getenv("COW_API_SERVICE_HOST_NAME")
	COWAPIServicePortNo   = os.Getenv("COW_API_SERVICE_PORT_NUMBER")
	COWAPIServiceURL      = fmt.Sprintf("%s://%s:%s", COWAPIServiceProtocol, COWAPIServiceHostName, COWAPIServicePortNo)

	COWWebserverProtocol = os.Getenv("COW_WEBSERVER_PROTOCOL")
	COWWebserverHostName = os.Getenv("COW_WEBSERVER_HOST_NAME")
	COWWebserverPortNo   = os.Getenv("COW_WEBSERVER_PORT_NUMBER")
	COWWebserverURL      = fmt.Sprintf("%s://%s:%s", COWWebserverProtocol, COWWebserverHostName, COWWebserverPortNo)
)

var USERHOMEDIR string

func UserHomeDir() string {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	return userHomeDir
}

var (
	CowDataTaskPath              = getEnv("POLICYCOW_TASKPATH", "/policycow/catalog/globalcatalog/tasks")
	CowDataRulesPath             = getEnv("POLICYCOW_RULESPATH", "/policycow/catalog/globalcatalog/rules")
	CowDataExecutionsPath        = getEnv("POLICYCOW_EXECUTIONPATH", "/policycow/catalog/globalcatalog/cowexecutions")
	CowDataRuleGroupPath         = getEnv("POLICYCOW_RULEGROUPPATH", "/policycow/catalog/globalcatalog/rulegroups")
	CowDataSynthesizerPath       = getEnv("POLICYCOW_SYNTHESIZERPATH", "/policycow/catalog/globalcatalog/synthesizers")
	CowDataDownloadsPath         = getEnv("POLICYCOW_DOWNLOADSPATH", "/policycow/exported-data")
	CowDataApplicationScopePath  = getEnv("POLICYCOW_APPLICATIONSCOPEPATH", "/policycow/catalog/globalcatalog/applicationscope")
	CowDataYamlFilesPath         = getEnv("POLICYCOW_YAMLFILESPATH", "/policycow/catalog/globalcatalog/yamlfiles")
	CowDataDashboardsFilesPath   = getEnv("POLICYCOW_DASHBOARDSPATH", "/policycow/catalog/globalcatalog/dashboards")
	CowDataDefaultConfigFilePath = getEnv("POLICYCOW_DEFAULTCONFIGPATH", "/policycow/etc/cowconfig.yaml")
	CowDataDeclarativesFilesPath = getEnv("POLICYCOW_DECLARATIVES_PATH", "/policycow/catalog/globalcatalog/declaratives")
	CowDataAppConnectionPath     = getEnv("POLICYCOW_DASH_APP_CONNECTIONS_PATH", "/policycow/catalog/appconnections")
	CowApplicationClassPath      = getEnv("POLICYCOW_APPLICATION_CLASS_PATH", "/policyCow/catalog/globalcatalog/yamlfiles/applications")
	CowCredentialsPath           = getEnv("POLICYCOW_CREDENTIALS_PATH", "/policyCow/catalog/globalcatalog/yamlfiles/credentials")

	CowPublishSubDomain   = getEnv("COW_SUB_DOMAIN", "partner")
	CowPublishDomain      = getEnv("COW_HOST_NAME", "compliancecow.live")
	CowClientID           = getEnv("COW_CLIENT_ID", "")
	CowClientSecret       = getEnv("COW_CLIENT_SECRET", "")
	ExecutionsFile        = "execution.ndjson"
	RuleFile              = "rule.json"
	RuleYamlFile          = "rule.yaml"
	TaskInputYAMLFile     = "inputs.yaml"
	TaskInputs__YAMLFile  = "inputs__.yaml"
	RuleGroupFile         = "rules_dependency.json"
	RuleGroupYAMLFileName = "rulegroup.yaml"
	TaskMetaYAMLFileName  = "__meta.yaml"
	LogsFileName          = "logs.txt"
	LocalFolder           = getEnv("LOCAL_FOLDER", "userdata")
	InputMetaFileType     = "FILE"
	MinioFilePath         = "<<MINIO_FILE_PATH>>"
)
var (
	PolicyCowConfig *vo.PolicyCowConfig = &vo.PolicyCowConfig{PathConfiguration: &vo.CowPathConfiguration{TasksPath: CowDataTaskPath, RulesPath: CowDataRulesPath, ExecutionPath: CowDataExecutionsPath, RuleGroupPath: CowDataRuleGroupPath}}
)

type SupportedLanguage int64

const (
	EmptySupportedLanguage SupportedLanguage = iota
	SupportedLanguageGo
	SupportedLanguagePython
)

func (s SupportedLanguage) String() string {
	switch s {
	case SupportedLanguageGo:
		return "go"
	case SupportedLanguagePython:
		return "python"
	}
	return "go"
}

func (s SupportedLanguage) GetSupportedLanguage(source string) (*SupportedLanguage, error) {
	supportedLanguage := EmptySupportedLanguage
	switch source {
	case "go":
		supportedLanguage = SupportedLanguageGo
	case "python":
		supportedLanguage = SupportedLanguagePython
	}

	if supportedLanguage == EmptySupportedLanguage {
		return nil, errors.New("not a valid programming language")
	}

	return &supportedLanguage, nil
}

type SQLDataSource int64

const (
	EmptySQLSource SQLDataSource = iota
	SQLDataSourceAPIEndpoint
	SQLDataSourceDatabase
	SQLDataSourceSQLRule
	SQLDataSourceTask
	SQLDataSourceRule
	SQLDataSourceNetworkFileShare
)

func (s SQLDataSource) String() string {
	switch s {
	case SQLDataSourceAPIEndpoint:
		return "api"
	case SQLDataSourceDatabase:
		return "db"
	case SQLDataSourceSQLRule:
		return "sqlrule"
	case SQLDataSourceTask:
		return "task"
	case SQLDataSourceRule:
		return "rule"
	case SQLDataSourceNetworkFileShare:
		return "networkfileshare"
	default:
		return "empty"
	}
}

func (s SQLDataSource) GetSQLDataSource(source string) (*SQLDataSource, error) {
	sqlDataSource := EmptySQLSource
	switch source {
	case "api":
		sqlDataSource = SQLDataSourceAPIEndpoint
	case "db":
		sqlDataSource = SQLDataSourceDatabase
	case "sqlrule":
		sqlDataSource = SQLDataSourceSQLRule
	case "task":
		sqlDataSource = SQLDataSourceTask
	case "rule":
		sqlDataSource = SQLDataSourceRule
	case "networkfileshare":
		sqlDataSource = SQLDataSourceNetworkFileShare
	}

	if sqlDataSource == EmptySQLSource {
		return nil, errors.New("not a valid source")
	}

	return &sqlDataSource, nil
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return defaultValue
	}
	return value
}

var TerminateKeys = []tea.KeyType{tea.KeyCtrlC, tea.KeyCtrlZ}
var UserTerminationMessage = "user termination"

const (
	EnvMinioRootUser     = "MINIO_ROOT_USER"
	EnvMinioRootPassword = "MINIO_ROOT_PASSWORD"
	EnvMinioLoginURL     = "MINIO_LOGIN_URL"
)

const RuleExecutionLogFile = "logs.txt"
const RuleExecutionLogKey = "logs"
const RuleExecutionLogDataFile = "RuleLogs.json"
const RuleExecutionLogDataKey = "RuleLogs_"
const TaskExecutionLogDataFile = "TaskLogs.ndjson"

const (
	BucketNameLog        = "logs"
	BucketNameRuleInputs = "ruleinputs"
)

const (
	ExecutionTypeRule      = "rule"
	ExecutionTypeRuleGroup = "rulegroup"
)

const (
	CowAttributeTypeBytes = "Bytes"
)

const (
	ComplianceStatusCompliant     = "COMPLIANT"
	ComplianceStatusNonCompliant  = "NON_COMPLIANT"
	ComplianceStatusNotDetermined = "NOT_DETERMINED"
)

const (
	CatalogTypeLocal  = "localcatalog"
	CatalogTypeGlobal = "globalcatalog"
)

const AppConnections = "appconnections"

const (
	FileNameTaskOutput = "task_output.json"
	FileNameTaskInput  = "task_input.json"
	FileNameProgress   = "progress.json"
)

const ProgressFolderName = "progress"

// Auth headers
var (
	AuthToken       = "Authtoken"
	Authorization   = "Authorization"
	SecurityContext = "X-Cow-Security-Context"
)
