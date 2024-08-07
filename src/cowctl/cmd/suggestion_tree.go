package cmd

import (
	complete "github.com/chriswalz/complete/v3"
	"github.com/spf13/cobra"
)

func toAutoCLI(suggs []complete.Suggestion) func(prefix string) []complete.Suggestion {
	return func(prefix string) []complete.Suggestion {
		return suggs
	}
}

func CreateSuggestionMap(cmd *cobra.Command) (*complete.CompTree, map[string]*cobra.Command) {
	_, continubeCmdMap := AllContinubeSubCommands(cmd)
	suggestionTree := rootSuggestionTree
	return suggestionTree, continubeCmdMap
}
