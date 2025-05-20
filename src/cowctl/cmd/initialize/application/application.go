package application

import (
	"cowlibrary/applications"
	"cowlibrary/constants"
	cowlibutils "cowlibrary/utils"
	"cowlibrary/vo"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/kyokomi/emoji"
	"github.com/spf13/cobra"

	"cowctl/utils"
	"cowctl/utils/terminalutils"
	"cowctl/utils/validationutils"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args: cobra.NoArgs,

		Use:   "application-type",
		Short: "Initialize a application-type",
		Long:  "Initialize application-type and reports",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd)
		},
	}

	cmd.Flags().StringP("name", "n", "", "Set your application name")
	cmd.Flags().String("version", "", "version of application.")
	cmd.Flags().String("config-path", "", "path for the configuration file.")
	cmd.Flags().Bool("can-override", false, "rule already exists in the system")
	cmd.Flags().StringSlice("credential", nil, "Set the credentials with version in format name:version")
	cmd.Flags().Bool("linked-application", false, "To link an application")
	return cmd
}

func runE(cmd *cobra.Command) error {

	additionalInfo, err := utils.GetAdditionalInfoFromCmd(cmd)
	if err != nil {
		return err
	}
	isDefaultConfigPath := cowlibutils.IsDefaultConfigPath(constants.CowDataDefaultConfigFilePath)
	applicationName := utils.GetFlagValueAndResetFlag(cmd, "name", "")
	applicationVersion := utils.GetFlagValueAndResetFlag(cmd, "version", "")

	if currentFlag := cmd.Flags().Lookup("can-override"); currentFlag != nil && currentFlag.Changed {
		if flagValue := currentFlag.Value.String(); cowlibutils.IsNotEmpty(flagValue) {
			currentFlag.Value.Set("false")
			additionalInfo.CanOverride, _ = strconv.ParseBool(flagValue)
		}
	}

	if cowlibutils.IsEmpty(applicationName) {
		if !isDefaultConfigPath {
			return errors.New("Set the application name using the 'name' flag")
		}
		applicationNameFromCmd, err := utils.GetValueAsStrFromCmdPrompt("ApplicationType Name (only alphabets and must start with a capital letter)", true, validationutils.ValidateAlphaName)
		if err != nil {
			return fmt.Errorf("invalid ApplicationType name. dashboard name:%s,err:%v", applicationNameFromCmd, err)
		}

		applicationName = applicationNameFromCmd

	}

	credentials, err := cmd.Flags().GetStringSlice("credential")
	if err != nil {
		return err
	}

	if !isDefaultConfigPath && cowlibutils.IsEmptyArray(credentials) {
		return errors.New("no credentials provided. Provide credentials by set the flag --credential=name:version")
	}

	appFilePath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationTypeConfigPath, cowlibutils.GetYAMLFileNameWithoutVersion(&vo.CowNamePointersVO{Name: applicationName, Version: applicationVersion}))

	if cowlibutils.IsFileExist(appFilePath) && !additionalInfo.CanOverride {
		if !isDefaultConfigPath && !additionalInfo.CanOverride {
			return errors.New("The ApplicationType is already present in the system. To want to re-initialize again, set the 'can-override' flag as true")
		}
		isConfirmed, err := utils.GetConfirmationFromCmdPrompt("ApplicationType already presented in the system. Are you going to re-initialize again ?")

		if err != nil {
			return err
		}

		if !isConfirmed {
			return nil
		}

		additionalInfo.CanOverride = true
	}

	var selectedCredentials []vo.CredentialItem
	for _, credential := range credentials {
		parts := strings.SplitN(credential, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid credential format: %s. expected format is name:version", credential)
		}

		selectedCredentials = append(selectedCredentials, vo.CredentialItem{Name: parts[0], Version: parts[1]})
	}

	credentialsPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.DeclarativePath, constants.UserDefinedCredentialsPath)

	if cowlibutils.IsFolderNotExist(credentialsPath) {
		return errors.New("credentials not available for selection. please create credential")
	}

	for _, credential := range selectedCredentials {
		if cowlibutils.IsFileNotExist(filepath.Join(credentialsPath, credential.Name)) {
			return fmt.Errorf("%s credential is not present in the system", credential.Name)
		}
		versions, _ := terminalutils.GetCredentialVersions(filepath.Join(credentialsPath, credential.Name))
		if !slices.Contains(versions, credential.Version) {
			return fmt.Errorf("%s version is not available for the %s credential", credential.Version, credential.Name)
		}
	}

	if isDefaultConfigPath && cowlibutils.IsEmptyArray(credentials) {
		selectedCredentials, err = terminalutils.GetCredentialWithVersionFromCMD(true, credentialsPath, []string{strings.ToLower(applicationName)})
		if err != nil {
			return err
		}
	}

	additionalInfo.CredentialInfo = selectedCredentials

	userInput := "no"

	if userInput == "yes" {
		selectedAppItems, err := terminalutils.GetApplicationNamesFromCmdPromptInCatalogs("Select the ApplicationType : ", true, []string{additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationTypeConfigPath})
		if err != nil {
			return err
		}
		additionalInfo.LinkedApplications = selectedAppItems
	}

	namePointer := &vo.CowNamePointersVO{Name: applicationName, Version: applicationVersion}

	errorDetails := applications.Init(namePointer, additionalInfo)

	if len(errorDetails) > 0 {
		if strings.Contains(errorDetails[0].Issue, constants.ErrorCredentialsAlreadyAvailable) {
			isConfirmed, err := utils.GetConfirmationFromCmdPrompt("ApplicationType already presented in the system. Are you going to re-initialize again ?")

			if err != nil {
				return err
			}

			if !isConfirmed {
				return nil
			}

			additionalInfo.CanOverride = true

			errorDetails = applications.Init(namePointer, additionalInfo)
		}
		if len(errorDetails) > 0 {
			utils.DrawErrorTable(errorDetails)
			return errors.New(constants.ErroInvalidData)
		}
	}

	emoji.Println("ApplicationType template has been created :smiling_face_with_sunglasses:! feel free to modify the template. you can see the ApplicationType yaml at ", filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationTypeConfigPath, cowlibutils.GetYAMLFileNameWithoutVersion(namePointer)))
	additionalInfo.GlobalCatalog = false
	return err
}
