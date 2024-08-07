package terminalutils

import (
	"cowlibrary/constants"
	"cowlibrary/utils"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/reflow/wordwrap"
	"golang.org/x/term"
)

const listHeight = 14

var (
	titleStyle        = lipgloss.NewStyle().MarginLeft(2)
	itemStyle         = lipgloss.NewStyle().PaddingLeft(4)
	selectedItemStyle = lipgloss.NewStyle().PaddingLeft(2).Foreground(lipgloss.Color("170"))
	paginationStyle   = list.DefaultStyles().PaginationStyle.PaddingLeft(4)
	helpStyle         = list.DefaultStyles().HelpStyle.PaddingLeft(4).PaddingBottom(1)
	quitTextStyle     = lipgloss.NewStyle().Margin(1, 0, 2, 4)
)

type item string

func (i item) FilterValue() string { return "" }

type itemDelegate struct{}

func (d itemDelegate) Height() int                             { return 1 }
func (d itemDelegate) Spacing() int                            { return 0 }
func (d itemDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil }
func (d itemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	i, ok := listItem.(item)
	if !ok {
		return
	}

	str := fmt.Sprintf("%d. %s", index+1, i)

	fn := itemStyle.Render
	if index == m.Index() {
		fn = func(s ...string) string {
			return selectedItemStyle.Render("> " + strings.Join(s, " "))
		}
	}

	fmt.Fprint(w, fn(str))
}

type listModel struct {
	list      list.Model
	choice    string
	quitting  bool
	labelName string
	err       error
}

func (m listModel) Init() tea.Cmd {
	return nil
}

func (m listModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetWidth(msg.Width + 200)
		return m, nil

	case tea.KeyMsg:
		switch {
		case utils.Contains(msg.Type, constants.TerminateKeys):
			m.quitting = true
			m.err = errors.New(constants.UserTerminationMessage)
			return m, tea.Quit

		case msg.Type == tea.KeyEnter:
			i, ok := m.list.SelectedItem().(item)
			if ok {
				m.choice = string(i)
			}
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m listModel) View() string {
	if utils.IsNotEmpty(m.choice) {
		return quitTextStyle.Render(m.labelName, "\n", m.choice)
	}
	if m.quitting {
		return quitTextStyle.Render("Nothing selected!")
	}
	return "\n" + m.list.View()
}

func GetConfirmationFromCmdPrompt(labelName string) (bool, error) {

	choice, err := GetOptionFromCmdPrompt(labelName, "Yes", []string{"Yes", "No"})
	if err != nil {
		return false, err
	}
	if choice == "Yes" {
		return true, nil
	}
	return false, nil

}

func GetOptionFromCmdPrompt(labelName, defaultOption string, options []string) (string, error) {
	items := make([]list.Item, 0)
	if utils.IsNotEmpty(defaultOption) {
		if defaultIndex := slices.Index(options, defaultOption); defaultIndex > 0 {
			options = append(options[:defaultIndex], options[defaultIndex+1:]...)
			options = append([]string{defaultOption}, options...)
		}
	}
	if len(options) > 0 {
		for _, option := range options {
			items = append(items, item(option))
		}
	} else {
		return "", errors.New("no data to select")
	}

	const defaultWidth = 20
	terminalWidth, _, _ := term.GetSize(0)
	labelName = wordwrap.String(labelName, terminalWidth-10)
	l := list.New(items, itemDelegate{}, defaultWidth, len(options)+8)
	l.Title = labelName
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.Styles.Title = titleStyle
	l.Styles.PaginationStyle = paginationStyle
	l.Styles.HelpStyle = helpStyle

	m := listModel{list: l, labelName: labelName}

	mm, err := tea.NewProgram(m).Run()

	m = mm.(listModel)

	if m.err != nil {
		return "", m.err
	}

	return m.choice, err

}
