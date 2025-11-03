package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	cowlibutils "cowlibrary/utils"

	prompt "github.com/arul-g/go-prompt"
	complete "github.com/chriswalz/complete/v3"
	"github.com/google/shlex"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func AllContinubeSubCommands(rootCmd *cobra.Command) ([]*cobra.Command, map[string]*cobra.Command) {
	bitCmds := rootCmd.Commands()
	bitCmdMap := map[string]*cobra.Command{}
	for _, bitCmd := range bitCmds {
		bitCmdMap[bitCmd.Name()] = bitCmd
	}
	return bitCmds, bitCmdMap
}

type Exit int

func exit(_ *prompt.Buffer) {
	panic(Exit(0))
}

func HandleExit() {
	switch v := recover().(type) {
	case nil:
		return
	case Exit:
		HandleCmdFunkyness()
		os.Exit(int(v))
	default:
		fmt.Println(v)
		HandleCmdFunkyness()
	}
}

func HandleCmdFunkyness() {
	cmd := exec.Command("stty", "sane")
	cmd.Stdin = os.Stdin
	cmd.Output()
}

func Find(slice []string, val string) int {
	for i, item := range slice {
		if item == val {
			return i
		}
	}
	return -1
}

func specificCommandCompleter(subCmd string, suggestionMap *complete.CompTree) func(d prompt.Document) []prompt.Suggest {
	return func(d prompt.Document) []prompt.Suggest {
		return promptCompleter(suggestionMap, subCmd+" "+d.Text)
	}
}

func promptCompleter(suggestionTree *complete.CompTree, text string) []prompt.Suggest {
	text = "cowctl " + text

	var sugg []prompt.Suggest
	queryFunc := strings.HasPrefix

	split, err := shlex.Split(strings.TrimSpace(text))
	if err != nil {
		log.Debug().Err(err).Send()
		return sugg
	}
	lastToken := split[len(split)-1]

	suggestions, err := complete.CompleteLine(text, suggestionTree, queryFunc)
	if err != nil {
		log.Debug().Err(err).Send()
		return sugg
	}

	for _, suggestion := range suggestions {
		name := suggestion.Name
		if strings.HasPrefix(lastToken, "-") && !strings.HasSuffix(text, " ") {
			name = "-" + suggestion.Name
			if len(name) > 2 {
				name = "-" + name
			}
		}
		sugg = append(sugg, prompt.Suggest{
			Text:        name,
			Description: suggestion.Desc,
		})
	}

	if text == "cowctl " {
		sugg = append(CobraCommandToSuggestions(CommonCommandsList()), sugg...)
	}

	return prompt.FilterHasPrefix(sugg, "", true)
}

func CommonCommandsList() []*cobra.Command {
	return []*cobra.Command{
		{
			Use:   "init",
			Short: "Initialize the rule/task",
		},
		{
			Use:   "init rule",
			Short: "Initialize the rule",
		},
		{
			Use:   "init rule-list",
			Short: "Initialize the rule-list",
		},
		{
			Use:   "init application-type",
			Short: "Initialize the application-type",
		},
		{
			Use:   "init credential-type",
			Short: "Initialize the credential-type",
		},
		{
			Use:   "create application-type",
			Short: "Create the application-type from YAML",
		},
		{
			Use:   "create credential-type",
			Short: "Create the credential-type from YAML",
		},
		{
			Use:   "publish rule",
			Short: "Publish the rule in ComplianceCow",
		},
		{
			Use:   "publish application-type",
			Short: "Publish the application-type in ComplianceCow",
		},
		{
			Use:   "publish rule-list",
			Short: "Publish the list of rules in ComplianceCow",
		},
		{
			Use:   "exec rule",
			Short: "Execute a rule",
		},
		{
			Use:   "exec rulegroup",
			Short: "Execute a rulegroup",
		},
		{
			Use:   "export rule",
			Short: "Export the rule",
		},
	}
}

func CobraCommandToSuggestions(cmds []*cobra.Command) []prompt.Suggest {
	var suggestions []prompt.Suggest
	for _, branch := range cmds {
		suggestions = append(suggestions, prompt.Suggest{
			Text:        branch.Use,
			Description: branch.Short,
		})
	}
	return suggestions
}

func HijackContinubeCommandOccurred(args []string, suggestionMap *complete.CompTree) bool {
	sub := args[0]
	if (sub == "init" || sub == "exec" || sub == "prep") && len(args) == 1 {
		branchName := SuggestionPrompt("> cowctl "+sub+" ", specificCommandCompleter(sub, suggestionMap))
		RunInTerminalWithColor("git", []string{"merge", branchName})
		return true
	}
	return false
}

func RunInTerminalWithColor(cmdName string, args []string) error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	return RunInTerminalWithColorInDir(cmdName, dir, args)
}

func RunInTerminalWithColorInDir(cmdName string, dir string, args []string) error {
	log.Debug().Msg(cmdName + " " + strings.Join(args, " "))

	_, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}

	cmd := exec.Command(cmdName, args...)
	cmd.Dir = dir
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if runtime.GOOS != "windows" {
		cmd.ExtraFiles = []*os.File{w}
	}

	err = cmd.Run()
	log.Debug().Err(err).Send()
	return err
}

type PromptTheme struct {
	PrefixTextColor             prompt.Color
	SelectedSuggestionBGColor   prompt.Color
	SuggestionBGColor           prompt.Color
	SuggestionTextColor         prompt.Color
	SelectedSuggestionTextColor prompt.Color
	DescriptionBGColor          prompt.Color
	DescriptionTextColor        prompt.Color
}

var DefaultTheme = PromptTheme{
	PrefixTextColor:             prompt.Yellow,
	SelectedSuggestionBGColor:   prompt.Yellow,
	SuggestionBGColor:           prompt.Yellow,
	SuggestionTextColor:         prompt.DarkGray,
	SelectedSuggestionTextColor: prompt.Blue,
	DescriptionBGColor:          prompt.Black,
	DescriptionTextColor:        prompt.White,
}

var InvertedTheme = PromptTheme{
	PrefixTextColor:             prompt.Blue,
	SelectedSuggestionBGColor:   prompt.LightGray,
	SelectedSuggestionTextColor: prompt.White,
	SuggestionBGColor:           prompt.Blue,
	SuggestionTextColor:         prompt.White,
	DescriptionBGColor:          prompt.LightGray,
	DescriptionTextColor:        prompt.Black,
}

var MonochromeTheme = PromptTheme{}

func SuggestionPrompt(prefix string, completer func(d prompt.Document) []prompt.Suggest) string {
	theme := DefaultTheme
	themeName := os.Getenv("BIT_THEME")
	if strings.EqualFold(themeName, "inverted") {
		theme = InvertedTheme
	}
	if strings.EqualFold(themeName, "monochrome") {
		theme = MonochromeTheme
	}
	result := prompt.Input(prefix, completer,
		prompt.OptionTitle(""),
		prompt.OptionHistory([]string{}),
		prompt.OptionPrefixTextColor(theme.PrefixTextColor),
		prompt.OptionSelectedSuggestionBGColor(theme.SelectedSuggestionBGColor),
		prompt.OptionSuggestionBGColor(theme.SuggestionBGColor),
		prompt.OptionSuggestionTextColor(theme.SuggestionTextColor),
		prompt.OptionSelectedSuggestionTextColor(theme.SelectedSuggestionTextColor),
		prompt.OptionDescriptionBGColor(theme.DescriptionBGColor),
		prompt.OptionDescriptionTextColor(theme.DescriptionTextColor),
		prompt.OptionShowCompletionAtStart(),
		prompt.OptionCompletionOnDown(),
		prompt.OptionSwitchKeyBindMode(prompt.EmacsKeyBind),
		prompt.OptionAddKeyBind(prompt.KeyBind{
			Key: prompt.ControlC,
			Fn:  exit,
		}),
		prompt.OptionAddASCIICodeBind(prompt.ASCIICodeBind{
			ASCIICode: []byte{0x1b, 0x62},
			Fn:        prompt.GoLeftWord,
		}),
		prompt.OptionAddASCIICodeBind(prompt.ASCIICodeBind{
			ASCIICode: []byte{0x1b, 0x66},
			Fn:        prompt.GoRightWord,
		}),
	)

	return strings.TrimSpace(result)
}

func RunContinubeCommandWithArgs(args []string) {
	var err error
	err = RunInTerminalWithColor("cowctl", args)
	if err != nil {
		log.Debug().Msg("Command may not exist: " + err.Error())
	}
	return
}

func parseCommandLine(command string) ([]string, error) {
	var args []string
	state := "start"
	current := ""
	quote := "\""
	escapeNext := true
	for i := 0; i < len(command); i++ {
		c := command[i]

		if state == "quotes" {
			if string(c) != quote {
				current += string(c)
			} else {
				args = append(args, current)
				current = ""
				state = "start"
			}
			continue
		}

		if escapeNext {
			current += string(c)
			escapeNext = false
			continue
		}

		if c == '\\' {
			escapeNext = true
			continue
		}

		if c == '"' || c == '\'' {
			state = "quotes"
			quote = string(c)
			continue
		}

		if state == "arg" {
			if c == ' ' || c == '\t' {
				args = append(args, current)
				current = ""
				state = "start"
			} else {
				current += string(c)
			}
			continue
		}

		if c != ' ' && c != '\t' {
			state = "arg"
			current += string(c)
		}
	}

	if state == "quotes" {
		return []string{}, fmt.Errorf("Unclosed quote in command line: %s", command)
	}

	if current != "" {
		args = append(args, current)
	}

	return args, nil
}

func ContinubeCli() {
	Execute()
}

var ValidateString = func(input string) error {
	if cowlibutils.IsEmpty(input) {
		return errors.New("Invalid value")
	}
	return nil
}
