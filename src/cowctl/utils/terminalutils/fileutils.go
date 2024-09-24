package terminalutils

import (
	"cowctl/utils/terminalutils/dropdownutils"
	"cowlibrary/constants"
	"cowlibrary/utils"
	"cowlibrary/vo"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/filepicker"
	tea "github.com/charmbracelet/bubbletea"
	"gopkg.in/yaml.v2"
)

type model struct {
	filepicker   filepicker.Model
	selectedFile string
	quitting     bool
	err          error
	promptMsg    string
}

type clearErrorMsg struct{}

func clearErrorAfter(t time.Duration) tea.Cmd {
	return tea.Tick(t, func(_ time.Time) tea.Msg {
		return clearErrorMsg{}
	})
}

func (m model) Init() tea.Cmd {
	return m.filepicker.Init()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case utils.Contains(msg.Type, constants.TerminateKeys):
			m.quitting = true
			m.err = errors.New(constants.UserTerminationMessage)
			return m, tea.Quit
		case msg.Type == tea.KeyEnter:
			if selected, path := m.filepicker.DidSelectFile(msg); selected {
				m.selectedFile = path
				m.err = nil
				m.quitting = true
				return m, tea.Quit
			}
		}
	case clearErrorMsg:
		m.err = nil
	}

	var cmd tea.Cmd
	m.filepicker, cmd = m.filepicker.Update(msg)

	// Did the user select a file?
	if didSelect, path := m.filepicker.DidSelectFile(msg); didSelect {
		// Get the path of the selected file.
		m.selectedFile = path
		// m.quitting = true
		return m, tea.Quit
	}

	// Did the user select a disabled file?
	// This is only necessary to display an error to the user.
	if didSelect, path := m.filepicker.DidSelectDisabledFile(msg); didSelect {
		// Let's clear the selectedFile and display an error.
		m.err = errors.New(path + " is not valid.")
		m.selectedFile = ""
		return m, tea.Batch(cmd, clearErrorAfter(2*time.Second))
	}

	return m, cmd
}

func (m model) View() string {
	var s strings.Builder

	if m.quitting {

		return ""
	}

	if m.err != nil {
		s.WriteString(m.filepicker.Styles.DisabledFile.Render(m.err.Error()))
	} else if utils.IsEmpty(m.selectedFile) {
		s.WriteString(m.promptMsg + ":")
	} else {
		s.WriteString("Selected file: " + m.filepicker.Styles.Selected.Render(filepath.Base(m.selectedFile)))
	}
	s.WriteString("\n\n" + m.filepicker.View() + "\n")
	return s.String()
}

func GetValueAsFileNameFromCmdPrompt(labelName string, isMandatory bool, pathPrefix string, supportedFileFormats []string) (string, error) {

	fp := filepicker.New()

	fp.AllowedTypes = supportedFileFormats
	fp.CurrentDirectory = pathPrefix
	m := model{
		filepicker: fp,
		promptMsg:  labelName,
	}

	tm, _ := tea.NewProgram(&m, tea.WithOutput(os.Stderr)).Run()
	mm := tm.(model)

	if mm.err != nil {
		return "", mm.err
	}

	return mm.selectedFile, nil
}

func GetCredentialWithVersionFromCMD(isMandatory bool, pathPrefix string, namesToBeIgnore []string) ([]vo.CredentialItem, error) {
	directories := make([]dropdownutils.Item, 0)

	if utils.IsFolderNotExist(pathPrefix) {
		return nil, errors.New("credential not found. please create and proceed")
	}
	files, err := os.ReadDir(pathPrefix)
	if err != nil {
		return nil, err
	}
	credWithVersionsMap := make(map[string][]string)

	for i, name := range namesToBeIgnore {
		namesToBeIgnore[i] = strings.ToLower(name)
	}

	sameNameAsCredential := false

	for _, file := range files {
		if file.IsDir() {
			directoryName := file.Name()

			// Skip the names which should be ignore
			if utils.SliceContains(namesToBeIgnore, strings.ToLower(directoryName)) {
				sameNameAsCredential = true
				continue
			}

			directories = append(directories, dropdownutils.Item{Name: directoryName})
			versions, err := GetCredentialVersions(filepath.Join(pathPrefix, directoryName))
			if err == nil && len(versions) > 0 {
				credWithVersionsMap[directoryName] = versions
			}

		}
	}
	if len(directories) == 0 {
		errorMsg := "credential not found. please create and proceed"
		if sameNameAsCredential {
			errorMsg = "credentials will be ignored if it contains same name as application. please add credential with different name"
		}
		return nil, errors.New(errorMsg)
	}
	return getCredentialsFromCMD(credWithVersionsMap, pathPrefix)
}

func getCredentialsFromCMD(credWithVersionsMap map[string][]string, pathPrefix string) ([]vo.CredentialItem, error) {
	credentials := make([]vo.CredentialItem, 0)
start:
	filteredDirctorires := make([]dropdownutils.Item, 0)
	for key, val := range credWithVersionsMap {
		if len(val) > 0 {
			filteredDirctorires = append(filteredDirctorires, dropdownutils.Item{Name: key})
		}
	}
	selectedDir, err := getSelectedValue("Select Credential (if the name is same as application name, will be ignored):", true, filteredDirctorires)
	if err != nil {
		return nil, err
	}
	filePath := filepath.Join(pathPrefix, selectedDir)
	filteredVersions := make([]dropdownutils.Item, 0)
	for _, version := range credWithVersionsMap[selectedDir] {
		filteredVersions = append(filteredVersions, dropdownutils.Item{Name: version})
	}
	selectedVersion, err := getSelectedValue("Choose version :", true, filteredVersions)
	if err != nil {
		return nil, err
	}
	credName, err := getCredentialNameFromFile(filepath.Join(filePath, selectedVersion))
	if err != nil {
		return nil, err
	}
	credentials = append(credentials, vo.CredentialItem{Name: credName, Version: selectedVersion, Directory: selectedDir})

	delete(credWithVersionsMap, credName)

	tempFilteredDirctorires := make([]dropdownutils.Item, 0)
	for key, val := range credWithVersionsMap {
		if len(val) > 0 {
			tempFilteredDirctorires = append(tempFilteredDirctorires, dropdownutils.Item{Name: key})
		}
	}
	userInput := "no"
	// INFO: As of now there's no limitation for choosing credential
	// if len(credentials) < 5 && len(tempFilteredDirctorires) > 0 {
	if len(tempFilteredDirctorires) > 0 {
		userInput, _ = GetOptionFromCmdPrompt("Would you like to add another credential?  yes/no (default:no):", "no", []string{"yes", "no"})
	}
	if userInput == "yes" {
		goto start
	}
	return credentials, nil
}

func GetApplicationNamesFromCmdPromptInCatalogs(labelName string, isMandatory bool, pathPrefixs []string) ([]vo.LinkedApplicationVO, error) {
	items := make([]vo.LinkedApplicationVO, 0)
	directories := make([]dropdownutils.Item, 0)
	for _, pattern := range pathPrefixs {
		matches, _ := filepath.Glob(pattern)
		for _, path := range matches {
			files, err := os.ReadDir(path)
			if err != nil {
				continue
			}
			for _, file := range files {
				if filepath.Ext(file.Name()) == ".yaml" {
					filePath := filepath.Join(path, file.Name())
					yamlContent, err := os.ReadFile(filePath)
					if err != nil {
						continue
					}
					var data *vo.UserDefinedApplicationVO
					if err := yaml.Unmarshal(yamlContent, &data); err != nil {
						continue
					}
					fullPath := filepath.Join(path, file.Name())
					descr := fmt.Sprintf("Name :%s", data.Meta.DisplayName)
					if utils.IsNotEmpty(data.Meta.Version) {
						descr += " , Version :" + data.Meta.Version
					}
					directories = append(directories, dropdownutils.Item{Name: data.Meta.Name, Descr: descr, Path: fullPath})
				}
			}
		}
	}
start:
	if len(directories) == 0 {
		return nil, errors.New("application class not found")
	}
	appName, err := getSelectedValue(labelName, isMandatory, directories)
	if err != nil {
		return nil, err
	}
	for _, item := range directories {
		if item.Name == appName {
			items = append(items, vo.LinkedApplicationVO{Name: item.Name, Descr: item.Descr, Path: item.Path})
		}
	}
	userInput := "no"
	directories = removeSelectedApplication(appName, directories)
	if len(directories) == 0 {
		return nil, errors.New("application class not found")
	}
	userInput, _ = GetOptionFromCmdPrompt("Would you like to link another application?  yes/no (default:no):", "no", []string{"yes", "no"})
	if userInput == "yes" {
		goto start
	}
	return items, nil
}

func removeSelectedApplication(appName string, directories []dropdownutils.Item) []dropdownutils.Item {
	result := make([]dropdownutils.Item, 0)
	for _, d := range directories {
		if d.Name != appName {
			result = append(result, d)
		}
	}
	return result
}

func removeSelectedVersion(selectedVersion string, versions []string) []string {
	result := []string{}
	for _, s := range versions {
		if s != selectedVersion {
			result = append(result, s)
		}
	}
	return result
}

func getCredentialNameFromFile(directory string) (string, error) {
	files, err := os.ReadDir(directory)
	if err != nil {
		return "", err
	}
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".yaml" {
			filePath := filepath.Join(directory, file.Name())
			yamlContent, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}
			var data *vo.UserDefinedCredentialVO
			if err := yaml.Unmarshal(yamlContent, &data); err != nil {
				continue
			}
			return data.Meta.Name, nil
		}
	}
	return "", nil
}

func GetCredentialVersions(path string) ([]string, error) {
	versions := make([]string, 0)
	files, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if file.IsDir() {
			versions = append(versions, file.Name())
		}
	}
	return versions, nil
}

func getSelectedValue(labelName string, isMandatory bool, directories []dropdownutils.Item) (string, error) {
	selectedValue, err := dropdownutils.GetOptionFromCmdPrompt(labelName, directories)
	if isMandatory && utils.IsEmpty(selectedValue) {
		return selectedValue, errors.New("value cannot be empty")
	}
	if !strings.HasPrefix(strings.TrimSpace(labelName), ":") {
		labelName += ":"
	}
	fmt.Printf("%s %s \n", labelName, selectedValue)
	return selectedValue, err
}
