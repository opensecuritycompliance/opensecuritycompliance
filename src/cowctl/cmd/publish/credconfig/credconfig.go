package credconfig

import (
	"cowlibrary/constants"
	"cowlibrary/credentials"
	cowlibutils "cowlibrary/utils"
	"cowlibrary/vo"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"cowctl/utils"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args: cobra.NoArgs,

		Use:   "credential",
		Short: "publish credential",
		Long:  "publish credential",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd)
		},
	}

	cmd.Flags().StringP("name", "n", "", "Set your credential name")
	cmd.Flags().String("version", "", "version of the credential.")
	cmd.Flags().String("config-path", "", "path for the configuration file.")

	return cmd
}

func runE(cmd *cobra.Command) error {

	additionalInfo, err := utils.GetAdditionalInfoFromCmd(cmd)
	if err != nil {
		return err
	}

	namePointer := &vo.CredentialsPointerVO{}

	if cmd.Flags().HasFlags() {

		if appNameFlag := cmd.Flags().Lookup("name"); appNameFlag != nil {
			namePointer.Name = appNameFlag.Value.String()

		}

		if versionFlag := cmd.Flags().Lookup("version"); versionFlag != nil {
			namePointer.Version = versionFlag.Value.String()
		}
	}

	credentialsPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.DeclarativePath, constants.UserDefinedCredentialsPath)

	if cowlibutils.IsEmpty(namePointer.Name) {
		namePointer.Name, err = utils.GetValueAsFolderNameFromCmdPrompt("Select the credential :", true, credentialsPath, utils.ValidateString)
		if err != nil {
			return fmt.Errorf("invalid app name. app name:%s,error:%v", namePointer.Name, err)
		}

		if cowlibutils.IsEmpty(namePointer.Name) {
			return fmt.Errorf("credential cannot be empty")
		}

		credentialsPath = filepath.Join(credentialsPath, strings.ToLower(namePointer.Name))
		if cowlibutils.IsFolderNotExist(credentialsPath) {
			return fmt.Errorf("credential not available")
		}
	}

	if cowlibutils.IsEmpty(namePointer.Version) {
		namePointer.Version, err = utils.GetValueAsFolderNameFromCmdPrompt("Select version :", true, credentialsPath, utils.ValidateString)
		if err != nil {
			return fmt.Errorf("invalid app name. app name:%s,error:%v", namePointer.Version, err)
		}

		if cowlibutils.IsEmpty(namePointer.Version) {
			return fmt.Errorf("credential cannot be empty")
		}
	}

	s := spinner.New(spinner.CharSets[38], 100*time.Millisecond) // Build our new spinner
	s.Prefix = "Publishing the credential..."
	s.Start()

	defer utils.StopSpinner(s)

	errorDetails := credentials.PublishCredential(namePointer, additionalInfo)
	if len(errorDetails) > 0 {
		if strings.Contains(errorDetails[0].Issue, constants.ErrorCredAlreadyPresent) {
			utils.StopSpinner(s)
			isConfirmed, err := utils.GetConfirmationFromCmdPrompt("Credential already presented in the system. Are you going to publish it again ?")

			if err != nil {
				return err
			}

			if !isConfirmed {
				return nil
			}

			s.Prefix = "Publishing the credential..."
			s.Start()

			additionalInfo.CanOverride = true

			errorDetails = credentials.PublishCredential(namePointer, additionalInfo)

		}
		if len(errorDetails) > 0 {
			utils.StopSpinner(s)
			utils.DrawErrorTable(errorDetails)
			return errors.New(constants.ErroInvalidData)
		}
	}

	utils.StopSpinner(s)

	d := color.New(color.FgCyan, color.Bold)
	d.Println("Hurray!.. Credential Configuration has been published on behalf of you")

	return err
}
