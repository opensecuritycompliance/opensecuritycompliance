package vo

type MinioFileVO struct {
	BucketName  string `json:"bucketName,omitempty" yaml:"bucketName,omitempty"`
	FileName    string `json:"fileName,omitempty" yaml:"fileName,omitempty" binding:"required"`
	Path        string `json:"path,omitempty" yaml:"path,omitempty"`
	FileContent []byte `json:"fileContent,omitempty" yaml:"fileContent,omitempty" binding:"required"`
	RuleName    string `json:"ruleName,omitempty" yaml:"ruleName,omitempty" binding:"required"`
}

type MinioFileInfoVO struct {
	FileURL string `json:"fileURL,omitempty" yaml:"fileURL,omitempty" binding:"required,http_url"`
}

type MinioFileInfoVOV2 struct {
	FileURL  string `json:"fileURL,omitempty" yaml:"fileURL,omitempty" binding:"required,http_url"`
	FileHash string `json:"fileHash,omitempty" yaml:"fileHash,omitempty"`
}

type AppliactionDetailsVO struct {
	Name   string
	Descr  string
	Path   string
	Global bool
}
