package terminalutils

// A simple program demonstrating the text input component from the Bubbles
// component library.

import (
	"cowctl/utils/validationutils"
	"cowlibrary/constants"
	"cowlibrary/utils"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

func GetValueFromCmdPrompt(labelName string, limit int, validator func(input string) error) (string, error) {

	if !strings.HasSuffix(strings.TrimSpace(labelName), ":") {
		labelName = labelName + " : "
	}

	ti := textinput.New()
	ti.Prompt = labelName
	ti.Focus()

	if limit > 0 {
		ti.CharLimit = limit
		ti.Width = limit
	}

	ti.Validate = validator
	txtMdl := textModel{
		textInput: ti,
		err:       nil,
		labelName: labelName,
	}

	p := tea.NewProgram(txtMdl)
	m, err := p.Run()
	if err != nil {
		return "", err
	}

	mm := m.(textModel)

	if mm.err != nil {
		return "", mm.err
	}

	fmt.Println(labelName + mm.selectedValue)
	return mm.selectedValue, nil

}

func GetValueAsStrFromCmdPrompt(labelName string) (string, error) {
	return GetValueFromCmdPrompt(labelName, validationutils.MaxLen, validationutils.ValidateString)
}

func GetValueAsIntFromCmdPrompt(labelName string, min, max int) (int, error) {

	validator := func(input string) error {
		num, err := strconv.Atoi(input)
		if err != nil || num < min || num > max {
			return errors.New("validation failed")
		}

		return nil
	}

	labelName = fmt.Sprintf(" %s(min: %d, max: %d)", labelName, min, max)

	valueFromCmd, err := GetValueFromCmdPrompt(labelName, 0, validator)
	if err != nil {
		return -1, err
	}

	value, err := strconv.Atoi(valueFromCmd)
	if err != nil {
		return -1, errors.New("invalid number")
	}

	return value, nil

}

type (
	errMsg error
)

type textModel struct {
	textInput     textinput.Model
	selectedValue string
	labelName     string
	err           error
	quitting      bool
}

func (m textModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m textModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc, tea.KeyCtrlQ:
			m.err = errors.New(constants.UserTerminationMessage)
			return m, tea.Quit
		case tea.KeyEnter:
			m.selectedValue = m.textInput.Value()
			if utils.IsNotEmpty(m.selectedValue) {
				m.err = nil
				m.quitting = true
				return m, tea.Quit
			}
		}

	// We handle errors just like any other message
	case errMsg:
		m.err = msg
		return m, nil
	}

	m.textInput, cmd = m.textInput.Update(msg)
	return m, cmd
}

func (m textModel) View() string {
	var s strings.Builder
	if m.quitting {
		return ""
	}

	// s.WriteString("\n")
	s.WriteString(m.textInput.View())
	// s.WriteString("\n")

	m.textInput.Reset()

	return s.String()
}
