package main

type UserInputs struct {
	ControlNumber string `yaml:"ControlNumber"`
	RuleConfig    string `yaml:"RuleConfig"`
}

type Outputs struct {
	CISBenchmarkForKubernetesFile string `yaml:"CISBenchmarkForKubernetesFile"`
	LogFile                       string `yaml:"LogFile"`
}
