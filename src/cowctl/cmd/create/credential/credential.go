package application

import (
	"cowlibrary/constants"
	"cowlibrary/credentials"
	cowlibutils "cowlibrary/utils"
	"cowlibrary/vo"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kyokomi/emoji"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"cowctl/utils"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "credential",
		Short: "Create a credential",
		Long:  "Create credential",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd)
		},
	}

	cmd.Flags().StringP("file-name", "f", "", "Set your file name")
	cmd.Flags().String("config-path", "", "path for the configuration file.")
	return cmd
}

func runE(cmd *cobra.Command) error {

	additionalInfo, err := utils.GetAdditionalInfoFromCmd(cmd)
	if err != nil {
		return err
	}

	yamlFileName, yamlFilePath := ``, ``

	if cmd.Flags().HasFlags() {
		if flagName := cmd.Flags().Lookup("yaml-file"); flagName != nil {
			yamlFileName = flagName.Value.String()
		}
	}

	if cowlibutils.IsNotEmpty(yamlFileName) {
		yamlFilePath = cowlibutils.GetYamlFilesPathFromApplicationCatalog(additionalInfo, yamlFileName)
	}

	if cowlibutils.IsEmpty(yamlFileName) || cowlibutils.IsFileNotExist(yamlFilePath) {
		fileNameFromCmd, err := utils.GetValueAsFileNameFromCmdPrompt("Select a valid yaml file name", additionalInfo.PolicyCowConfig.PathConfiguration.CredentialsPath, []string{".yaml", ".yml"})
		if err != nil || cowlibutils.IsEmpty(fileNameFromCmd) {
			return errors.New("cannot get the credential")
		}
		yamlFilePath = filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.CredentialsPath, fileNameFromCmd)
		if cowlibutils.IsFileNotExist(yamlFilePath) {
			return fmt.Errorf("%s is not a valid credential file path", yamlFilePath)
		}
	}

	yamlFileByts, err := os.ReadFile(yamlFilePath)
	if err != nil {
		return err
	}

	credential := &vo.UserDefinedCredentialVO{}
	err = yaml.Unmarshal(yamlFileByts, &credential)
	if err != nil {
		return err
	}

	additionalInfo.ApplictionScopeConfigVO = &vo.ApplictionScopeConfigVO{FileData: yamlFileByts}

	if credentials.IsCredentialAlreadyPresent(credential, additionalInfo) {
		isConfirmed, err := utils.GetConfirmationFromCmdPrompt("credential already presented in the directory. Are you sure you going to re-initialize ?")
		if !isConfirmed || err != nil {
			return err
		}
		credential.IsVersionToBeOverride = true
	}

	errorDetails := (&credentials.CredentialsHandler{Context: cmd.Context()}).Create(credential, additionalInfo)
	if len(errorDetails) > 0 {
		utils.DrawErrorTable(errorDetails)
		return errors.New(constants.ErroInvalidData)
	}

	emoji.Println("Credential creation is complete :smiling_face_with_sunglasses:! You can find the credential yaml at ", filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.DeclarativePath, "credentials"))

	return nil

}
