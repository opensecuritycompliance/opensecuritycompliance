package cmd

import (
	"fmt"
	"os"

	"strings"

	"github.com/spf13/cobra"

	create "cowctl/cmd/create"
	execute "cowctl/cmd/execute"
	export "cowctl/cmd/export"
	initialize "cowctl/cmd/initialize"
	publish "cowctl/cmd/publish"

	prompt "github.com/arul-g/go-prompt"
	complete "github.com/chriswalz/complete/v3"
	"github.com/rs/zerolog/log"
)

var cfgFile string

// ContinubeCmd represents the base command when called without any subcommands
var ContinubeCmd = &cobra.Command{
	Use:   "cowctl",
	Short: "cowctl cli for rule execution",
	Long:  `cowctl cli for rule execution. Everything will be offline`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
	Run: func(cmd *cobra.Command, args []string) {
		suggestionTree, bitCmdMap := CreateSuggestionMap(cmd)

		// TODO : Optional Interactive
		repeat := true
		repeatAmount := 1
		if repeat {
			repeatAmount = 5000
		}

		for i := repeatAmount; i > 0; i-- {
			HandleCmdFunkyness()
			resp := SuggestionPrompt("> cowctl ", shellCommandCompleter(suggestionTree))
			subCommand := resp
			if subCommand == "" {
				continue
			}
			if strings.Index(resp, " ") > 0 {
				subCommand = subCommand[0:strings.Index(resp, " ")]
			}
			parsedArgs, err := parseCommandLine(resp)
			if err != nil {
				log.Debug().Err(err).Send()
				continue
			}

			if helpCommand := strings.TrimSpace(resp); helpCommand == "--help" || helpCommand == "-h" {
				cmd.SetArgs(parsedArgs)
				cmd.Execute()
				continue
			}

			if bitCmdMap[subCommand] == nil {
				yes := HijackContinubeCommandOccurred(parsedArgs, suggestionTree)
				if yes {
					continue
				}
				RunContinubeCommandWithArgs(parsedArgs)
				continue
			}
			cmd.SetArgs(parsedArgs)
			cmd.Execute()
		}
	},
	PostRun: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Inside subCmd PostRun with args: %v\n", args)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(ContinubeCmd.Execute())
}

func init() {
	cobra.OnInitialize()

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	ContinubeCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cowruleexecutor.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	ContinubeCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	ContinubeCmd.AddCommand(initialize.NewCommand())
	ContinubeCmd.AddCommand(execute.NewCommand())
	ContinubeCmd.AddCommand(create.NewCommand())
	ContinubeCmd.AddCommand(export.NewCommand())
	ContinubeCmd.AddCommand(publish.NewCommand())
	ContinubeCmd.AddCommand(exitCmd)

}

var exitCmd = &cobra.Command{
	Args:  cobra.NoArgs,
	Use:   "exit",
	Short: "Exit from the cli",
	Long:  "Exit from the cli",
	RunE: func(cmd *cobra.Command, args []string) error {
		HandleCmdFunkyness()
		os.Exit(0)
		return nil
	},
}

func shellCommandCompleter(suggestionTree *complete.CompTree) func(d prompt.Document) []prompt.Suggest {
	return func(d prompt.Document) []prompt.Suggest {
		return promptCompleter(suggestionTree, d.Text)
	}
}
