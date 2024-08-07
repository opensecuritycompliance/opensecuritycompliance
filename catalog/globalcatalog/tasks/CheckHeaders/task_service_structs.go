package main

type UserInputs struct {
	HarFilePath         string `yaml:"HarFilePath"`
	AnalyzedHarFileName string `yaml:"AnalyzedHarFileName"`
	BucketName          string `yaml:"BucketName,omitempty"`
}

type Outputs struct {
	ComplianceStatus_              string
	CompliancePCT_                 int
	LogFile                        string
	ErrorDetails                   error
	StrictTransportSecurityLog     string `description:"log"`
	StdStrictTransportSecurityLog  string `description:"stdLog"`
	PublicKeyPinsLog               string `description:"log"`
	StdPublicKeyPinsLog            string `description:"stdLog"`
	ExpectCTLog                    string `description:"log"`
	StdExpectCTLog                 string `description:"stdLog"`
	XFrameOptionsLog               string `description:"log"`
	StdXFrameOptionsLog            string `description:"stdLog"`
	AccessControlAllowOriginLog    string `description:"log"`
	StdAccessControlAllowOriginLog string `description:"stdLog"`
	XContentTypeOptionsLog         string `description:"log"`
	StdXContentTypeOptionsLog      string `description:"stdLog"`
	RefererPolicyLog               string `description:"log"`
	StdRefererPolicyLog            string `description:"stdLog"`
	ETagLog                        string `description:"log"`
	StdETagLog                     string `description:"stdLog"`
}
