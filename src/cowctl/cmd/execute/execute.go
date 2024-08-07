package initialize

import (
	"errors"

	"github.com/spf13/cobra"

	"cowctl/cmd/execute/rule"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "exec",
		Short: "Execute rule",
		Long:  "Execute rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := cmd.Help()
			if err != nil {
				return err
			}
			return errors.New("Subcommand is required")
		},
	}
	cmd.AddCommand(rule.NewCommand())
	cmd.AddCommand(rule.NewRuleGroupCommand())

	return cmd
}
