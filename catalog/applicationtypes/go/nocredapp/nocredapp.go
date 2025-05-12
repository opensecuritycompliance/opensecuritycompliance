package nocredapp

import (
	"github.com/go-playground/validator/v10"
)

const (
	EpssAPI = "https://api.first.org/data/v1/epss?cve={{cve}}"
)

type NoCred struct {
	Dummy string `json:"dummy" yaml:"Dummy"`
}

type UserDefinedCredentials struct {
	NoCred NoCred `json:"noCred" yaml:"NoCred"`
}

type NoCredApp struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"port"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
}

func (thisObj *NoCredApp) Validate() (bool, error) {
	return true, nil
}

// INFO : You can implement your own implementation for the class
func (thisObj *NoCredApp) ValidateStruct(s interface{}) error {
	validate := validator.New()
	if err := validate.Struct(s); err != nil {
		return err
	}
	return nil
}
