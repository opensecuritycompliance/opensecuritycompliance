package credential

import (
	"cowlibrary/constants"
	"cowlibrary/credentials"
	cowlibutils "cowlibrary/utils"
	"cowlibrary/vo"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kyokomi/emoji"
	"github.com/spf13/cobra"

	"cowctl/utils"
	"cowctl/utils/validationutils"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args: cobra.NoArgs,

		Use:   "credential",
		Short: "Initialize a credential",
		Long:  "Initialize credential and reports",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd)
		},
	}

	cmd.Flags().StringP("name", "n", "", "Set your credential name")
	cmd.Flags().String("version", "", "version of credential.")
	cmd.Flags().String("config-path", "", "path for the configuration file.")
	return cmd
}

func runE(cmd *cobra.Command) error {

	additionalInfo, err := utils.GetAdditionalInfoFromCmd(cmd)
	if err != nil {
		return err
	}
	credentialName := utils.GetFlagValueAndResetFlag(cmd, "name", "")
	credentialVersion := utils.GetFlagValueAndResetFlag(cmd, "version", "")

	if cowlibutils.IsEmpty(credentialName) {
		credentialNameFromCmd, err := utils.GetValueAsStrFromCmdPrompt("Credential Name (only alphabets and must start with a capital letter)", true, validationutils.ValidateAlphaName)
		if err != nil {
			return fmt.Errorf("invalid credential name. dashboard name:%s,err:%v", credentialNameFromCmd, err)
		}

		credentialName = credentialNameFromCmd

	}

	if cowlibutils.IsEmpty(credentialVersion) {
		labelName := "Credential Version (semantic version, e.g. 1.1.1)"
	GetVersion:
		credentialVersionFromCmd, err := utils.GetValueAsStrFromCmdPrompt(labelName, true, validationutils.ValidateVersionTyping)

		if err != nil {
			return fmt.Errorf("invalid credential version. credential version:%s,err:%v", credentialVersionFromCmd, err)
		}

		if validationutils.ValidateVersion(credentialVersionFromCmd) != nil {
			labelName = "invalid credential version. please re-enter a valid version"
			goto GetVersion
		}

		credentialVersion = credentialVersionFromCmd

	}

	namePointer := &vo.CowNamePointersVO{Name: credentialName, Version: credentialVersion}

	credHandler := (&credentials.CredentialsHandler{Context: cmd.Context()})

	errorDetails := credHandler.Init(namePointer, additionalInfo)

	if len(errorDetails) > 0 {
		if strings.Contains(errorDetails[0].Issue, constants.ErrorCredentialsAlreadyAvailable) {
			isConfirmed, err := utils.GetConfirmationFromCmdPrompt("Credential already presented in the system. Are you going to re-initialize again ?")

			if err != nil {
				return err
			}

			if !isConfirmed {
				return nil
			}

			additionalInfo.CanOverride = true

			errorDetails = credHandler.Init(namePointer, additionalInfo)

		}
		if len(errorDetails) > 0 {
			utils.DrawErrorTable(errorDetails)
			return errors.New(constants.ErroInvalidData)
		}
	}

	emoji.Println("Credential template has been created :smiling_face_with_sunglasses:! you can see the credential yaml at ", filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.CredentialsPath, cowlibutils.GetYAMLFileNameWithVersion(namePointer)))
	additionalInfo.GlobalCatalog = false
	return err
}
