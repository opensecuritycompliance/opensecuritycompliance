package dropdownutils

import (
	"cowlibrary/constants"
	"cowlibrary/utils"
	"cowlibrary/vo"
	"errors"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var docStyle = lipgloss.NewStyle().Margin(1, 2)

type Item struct {
	Name   string
	Descr  string
	Path   string
	Global bool
}

func (i Item) Title() string       { return i.Name }
func (i Item) Description() string { return i.Descr }
func (i Item) FilterValue() string { return i.Name }
func (i Item) GetItem() Item       { return i }

type model struct {
	list                     list.Model
	selectedValue, labelName string
	quitting                 bool
	err                      error
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.list.FilterState() == list.Filtering {
			if !m.list.IsFiltered() {
				m.list.ResetSelected()
				break
			}
		}
		switch {
		case utils.Contains(msg.Type, constants.TerminateKeys):
			m.quitting = true
			m.err = errors.New(constants.UserTerminationMessage)
			return m, tea.Quit
		case msg.Type == tea.KeyEnter:
			if m.list.SelectedItem() != nil {
				m.selectedValue = m.list.SelectedItem().FilterValue()
				if utils.IsNotEmpty(m.selectedValue) {
					m.list.SetShowHelp(false)
					// return m, tea.Quit
				}
			}
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		h, v := docStyle.GetFrameSize()
		m.list.SetSize(msg.Width-h, msg.Height-v)
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)

	return m, cmd
}

func (m model) View() string {
	if utils.IsNotEmpty(m.selectedValue) {
		return docStyle.Render(m.labelName, "\n", m.selectedValue)
	}
	if m.quitting {
		return docStyle.Render("Nothing selected!")
	}
	return "\n" + m.list.View()
}

func GetOptionFromCmdPrompt(labelName string, options []Item) (string, error) {
	return GetOptionFromCmdPromptV2(labelName, options, nil)
}

func GetOptionFromCmdPromptV2(labelName string, options []Item, additionalInfo *vo.AdditionalInfo) (string, error) {

	if len(options) == 0 {
		return "", errors.New("no data to select")
	}

	items := make([]list.Item, 0)
	for _, option := range options {
		items = append(items, option)
	}

	modl := model{list: list.New(items, list.NewDefaultDelegate(), 0, 0), labelName: labelName}
	modl.list.Title = labelName

	m, err := tea.NewProgram(modl, tea.WithAltScreen(), tea.WithMouseAllMotion()).Run()
	if err != nil {
		return "", err
	}
	mm := m.(model)
	if mm.err != nil {
		return "", mm.err
	}

	if selectedItem := mm.list.SelectedItem(); selectedItem != nil {
		selectedItemObj, ok := selectedItem.(Item)
		if ok && additionalInfo != nil {
			additionalInfo.GlobalCatalog = selectedItemObj.Global
		}
	}

	mm.list.SetShowHelp(false)
	return mm.selectedValue, nil
}
