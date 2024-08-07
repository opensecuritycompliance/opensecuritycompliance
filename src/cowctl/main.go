package main

import (
	"cowctl/cmd"

	cowlibutils "cowlibrary/utils"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func main() {
	if cowlibutils.IsGoOutDated() {
		color.Red("the minimal go version to use the library is %s:", cowlibutils.MinGoVersion)
		return
	}
	defer cmd.HandleExit()
	cobra.CheckErr(cmd.ContinubeCmd.Execute())
}
