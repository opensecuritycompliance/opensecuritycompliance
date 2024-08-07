package vo

type SQLRuleVO struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Purpose       string `json:"purpose"`
		Description   string `json:"description"`
		Aliasref      string `json:"aliasref"`
		Sqldatasource struct {
			Sourcetype   string `json:"sourcetype"`
			Appselector  string `json:"appselector"`
			Ruleselector string `json:"ruleselector"`
			Inputs       []struct {
				Name           string `json:"name"`
				Shortname      string `json:"shortname"`
				Jmespathfilter string `json:"jmespathfilter,omitempty"`
			} `json:"inputs"`
		} `json:"sqldatasource"`
		Sqlstatements []struct {
			Name         string `json:"name"`
			Shortname    string `json:"shortname"`
			Description  string `json:"description"`
			Sqlstatement string `json:"sqlstatement"`
		} `json:"sqlstatements"`
		Outputs struct {
			Files []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
				Path        string `json:"path"`
				Format      string `json:"format"`
				Weight      int    `json:"weight"`
				Shortname   string `json:"shortname"`
			} `json:"files"`
			Compliancepct    string `json:"compliancepct"`
			Compliancestatus string `json:"compliancestatus"`
		} `json:"outputs"`
	} `json:"spec"`
}
