package prepare

import (
	"errors"

	"github.com/spf13/cobra"

	rule "cowctl/cmd/prepare/rule"
	task "cowctl/cmd/prepare/task"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args: cobra.NoArgs,

		Use:   "prep",
		Short: "Prepare one of [rule, task]",
		Long:  "Prepare one of [rule, task]",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := cmd.Help()
			if err != nil {
				return err
			}
			return errors.New("subcommand is required")
		},
	}
	cmd.AddCommand(task.NewCommand())
	cmd.AddCommand(rule.NewCommand())
	return cmd
}
