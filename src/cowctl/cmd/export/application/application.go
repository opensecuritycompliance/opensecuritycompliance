package application

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"cowctl/utils"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args: cobra.NoArgs,

		Use:   "application",
		Short: "Create application export file",
		Long:  "Create application export file",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd)
		},
	}

	cmd.Flags().String("application-path", "", "path of the application folder.")

	return cmd
}

func runE(cmd *cobra.Command) error {
	// fmt.Println("running command")
	additionalInfo, err := utils.GetAdditionalInfoFromCmd(cmd)
	if err != nil {
		fmt.Println("err:", err)
		return err
	}
	apps := utils.GetApplicationNamesForBinary([]string{additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationClassPath})
	jsonData, err := json.Marshal(apps)
    if err != nil {
		fmt.Println("err:", err)
        return err
    }

	fmt.Println(string(jsonData))
	return err
}
