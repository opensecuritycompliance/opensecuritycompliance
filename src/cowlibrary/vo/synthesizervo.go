package vo

type SynthesizerPublisherVO struct {
	WorkflowConfigName string         `json:"workflowConfigName,omitempty"`
	Input              *SynthesizerVO `json:"input,omitempty"`
}

type SynthesizerVO struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	FileBytes   []byte `json:"file_bytes,omitempty"`
	Level       string `json:"level,omitempty"`
}

type SynthesizerInfo struct {
	SynthesizerName string   `json:"synthesizerName,omitempty"`
	AliasRef        string   `json:"aliasref,omitempty"`
	DependsOn       []string `json:"dependsOn,omitempty"`
}
