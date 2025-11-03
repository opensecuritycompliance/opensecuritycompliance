package multiselect

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

type MultiSelectItem struct {
	Title       string
	Description string
	Selected    bool 
}

func (i MultiSelectItem) FilterValue() string { return i.Title }

// Styles
var (
	appStyle        = lipgloss.NewStyle().Padding(1, 2, 0, 2)
	titleStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFF")).Background(lipgloss.Color("#56B")).Padding(0, 1).Bold(true)
	itemStyle       = lipgloss.NewStyle().PaddingLeft(2)
	cursorItemStyle = itemStyle.Foreground(lipgloss.Color("34")).Bold(true)
)

type delegate struct{}

func (d delegate) Height() int                               { return 1 }
func (d delegate) Spacing() int                              { return 0 }
func (d delegate) Update(msg tea.Msg, m *list.Model) tea.Cmd { return nil }
func (d delegate) Render(w io.Writer, m list.Model, index int, li list.Item) {
	item := li.(MultiSelectItem)
	cursor := " "
	if index == m.Index() {
		cursor = ">"
	}

	line := fmt.Sprintf("%s %s", cursor, item.Title)

	if index == m.Index() {
		fmt.Fprint(w, cursorItemStyle.Render(line))
	} else {
		fmt.Fprint(w, lipgloss.NewStyle().Foreground(lipgloss.Color("")).Render(line))
	}
}

type model struct {
	list      list.Model
	selected  map[string]bool
	master    []MultiSelectItem
	done      bool
	lastEnter time.Time
	enterCnt  int
	width     int
	height    int
}

func (m model) Init() tea.Cmd { return tea.EnterAltScreen }

func (m *model) refreshList() {
	filtered := []list.Item{}
	for _, it := range m.master {
		if !m.selected[it.Title] {
			filtered = append(filtered, it)
		}
	}
	m.list.SetItems(filtered)
	m.list.ResetFilter() // ensures filter starts fresh
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.list.SetSize(m.width, max(m.height-7, 5))

	case tea.KeyMsg:
		switch msg.String() {
		case "f", "q", "ctrl+c":
			m.done = true
			return m, tea.Quit

		case " ", "enter":
			idx := m.list.Index()
			if idx < 0 || idx >= len(m.list.Items()) {
				break
			}

			item := m.list.SelectedItem().(MultiSelectItem)

			if msg.String() == "enter" {
				now := time.Now()
				if now.Sub(m.lastEnter) < 300*time.Millisecond {
					m.enterCnt++
				} else {
					m.enterCnt = 1
				}
				m.lastEnter = now
				if m.enterCnt >= 2 {
					m.done = true
					return m, tea.Quit
				}
			}

			m.selected[item.Title] = true
			for i := range m.master {
				if m.master[i].Title == item.Title {
					m.master[i].Selected = true
					break
				}
			}

			m.refreshList()
			if len(m.list.Items()) > 0 {
				m.list.Select(min(idx, len(m.list.Items())-1))
			}
		}
	}

	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m model) View() string {
	instructions := lipgloss.NewStyle().
		Bold(true).
		Render("[space/enter to select, double Enter or 'f' to finish | / filter, esc clear, q quit]")

	return appStyle.Render(m.list.View() + "\n" + instructions)
}

func RunMultiSelect(title string, options []MultiSelectItem) ([]string, error) {
	items := make([]list.Item, len(options))
	for i, o := range options {
		items[i] = o
	}

	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		width, height = 80, 24
	}

	l := list.New(items, delegate{}, max(width, 20), max(height-2, 5))
	l.Title = title
	l.SetFilteringEnabled(true)
	l.SetShowStatusBar(false)
	l.SetShowHelp(false)

	m := model{
		list:     l,
		selected: make(map[string]bool),
		master:   options,
		width:    width,
		height:   height,
	}

	final, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	if err != nil {
		return nil, err
	}

	res := final.(model)
	selected := []string{}
	for k := range res.selected {
		selected = append(selected, k)
	}
	return selected, nil
}

func max(a, b int) int {
	if a < b {
		return b
	}
	return a
}
