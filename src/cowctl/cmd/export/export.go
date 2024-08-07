package export

import (
	"errors"

	"github.com/spf13/cobra"

	"cowctl/cmd/export/application"
	"cowctl/cmd/export/rule"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args: cobra.NoArgs,

		Use:   "export",
		Short: "export one of [rulegroup, rule]",
		Long:  "export one of [rulegroup, rule]",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := cmd.Help()
			if err != nil {
				return err
			}
			return errors.New("subcommand is required")
		},
	}
	cmd.AddCommand(rule.NewCommand())
	cmd.AddCommand(rule.NewRuleGroupCommand())
	cmd.AddCommand(application.NewCommand())

	return cmd
}
