package commands

import (
	prompt "github.com/arul-g/go-prompt"
)

type Commands struct {
	ContinubeSuggestions    []prompt.Suggest
	ContinubeSubSuggestions map[string][]prompt.Suggest
}

func New() Commands {
	return Commands{
		ContinubeSuggestions: []prompt.Suggest{
			{Text: "init", Description: "Initialize a Rule or Task"},
			{Text: "exec", Description: "Execute a Rule"},
			{Text: "create", Description: "Create Rule/Task/Method with the help of yaml file"},
			{Text: "export", Description: "Export Rule/RuleGroup/Synthesizer"},
			{Text: "publish", Description: "Publish Rule/Synthesizer to compliance cow"},
		},
		ContinubeSubSuggestions: map[string][]prompt.Suggest{
			"init": []prompt.Suggest{
				{Text: "rule", Description: "Initialize a Rule"},
				{Text: "task", Description: "Initialize a Task"},
				{Text: "--path", Description: "path to the folder"},
			},
			"exec": []prompt.Suggest{
				{Text: "rule", Description: "Execute the rules"},
				{Text: "rulegroup", Description: "Execute the rulegroup"},
				{Text: "--path", Description: "path to the folder"},
			},

			"create": []prompt.Suggest{
				{Text: "--file-path", Description: "path to the yaml file"},
			},
			"export": []prompt.Suggest{
				{Text: "rule", Description: "Export the Rule"},
				{Text: "rulegroup", Description: "Export the RuleGroup"},
			},
			"publish": []prompt.Suggest{
				{Text: "rule", Description: "Publish the Rule"},
			},
			"apply": []prompt.Suggest{
				{Text: "-f", Description: "yaml file name"},
			},
		},
	}
}

func (c *Commands) GetContinubeSuggestions() []prompt.Suggest {
	return c.ContinubeSuggestions
}

func (c *Commands) GetContinubeSubSuggestions() map[string][]prompt.Suggest {
	return c.ContinubeSubSuggestions
}

func (c *Commands) IsContinubeCommand(kw string) bool {
	for _, cmd := range c.ContinubeSuggestions {
		if cmd.Text == kw {
			return true
		}
	}

	return false
}

func (c *Commands) IsContinubeSubCommand(kw string) ([]prompt.Suggest, bool) {
	val, ok := c.ContinubeSubSuggestions[kw]
	return val, ok
}
