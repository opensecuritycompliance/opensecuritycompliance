package vo

type ReportInputVO struct {
	Name     string
	Template string
}

type DashboardPublisherVO struct {
	WorkflowConfigId string       `json:"workflowConfigId,omitempty"`
	Input            *DashboardVO `json:"input,omitempty"`
}

type DashboardVO struct {
	Name        string `json:"name,omitempty"`
	CategoryID  string `json:"categoryID,omitempty"`
	Description string `json:"description,omitempty"`
	FileBytes   []byte `json:"file_bytes,omitempty"`
	Level       string `json:"level,omitempty"`
}

type ValidationError struct {
	MessageType string `json:"message_type"`
	Message     string `json:"message"`
	Description string `json:"description"`
}
type ValidationFile struct {
	FileContent string `json:"fileContent"`
}

type ValidationResponse struct {
	FileHash             string `json:"fileHash"`
	IsFileContainsIssues bool   `json:"isFileContainsIssues"`
}

type InsightCategory struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Level       string `json:"level"`
	ID          string `json:"id"`
	Status      string `json:"status,omitempty"`
	OrgID       string `json:"orgID,omitempty"`
	DomainID    string `json:"domainID,omitempty"`
	GroupID     string `json:"groupID,omitempty"`
	CraetedAt   string `json:"craetedAt,omitempty"`
	UpdatedAt   string `json:"updatedAt,omitempty"`
}
