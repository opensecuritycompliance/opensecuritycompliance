package initialize

import (
	"cowctl/cmd/initialize/application"
	"cowctl/cmd/initialize/credential"
	"errors"

	"cowctl/cmd/initialize/rule"
	ruleList "cowctl/cmd/initialize/rule-list"
	"cowctl/cmd/initialize/task"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args: cobra.NoArgs,

		Use:   "init",
		Short: "Inits one of [rule, task]",
		Long:  "Inits one of [rule, task]",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := cmd.Help()
			if err != nil {
				return err
			}
			return errors.New("subcommand is required")
		},
	}

	cmd.AddCommand(rule.NewCommand())
	cmd.AddCommand(ruleList.NewCommand())
	cmd.AddCommand(task.NewCommand())
	cmd.AddCommand(credential.NewCommand())
	cmd.AddCommand(application.NewCommand())

	return cmd
}
