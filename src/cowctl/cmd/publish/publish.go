package publish

import (
	"errors"

	"github.com/spf13/cobra"

	"cowctl/cmd/publish/appconfig"
	"cowctl/cmd/publish/rule"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args: cobra.NoArgs,

		Use:   "publish",
		Short: "publish one of [application, credential, rule, synthesizer]",
		Long:  "publish one of [application, credential, rule, synthesizer]",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := cmd.Help()
			if err != nil {
				return err
			}
			return errors.New("subcommand is required")
		},
	}
	cmd.AddCommand(rule.NewCommand())
	cmd.AddCommand(appconfig.NewCommand())

	return cmd
}
