package create

import (
	"errors"

	"github.com/spf13/cobra"

	app "cowctl/cmd/create/application"
	cred "cowctl/cmd/create/credential"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "create",
		Short: "create credential-type/application-type",
		Long:  "create credential-type/application-type",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := cmd.Help()
			if err != nil {
				return err
			}
			return errors.New("Subcommand is required")
		},
	}
	cmd.AddCommand(app.NewCommand())
	cmd.AddCommand(cred.NewCommand())

	return cmd
}
