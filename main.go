package main

import (
	"fmt"

	"github.com/ibnaleem/vtscan/cmd"
	"github.com/ibnaleem/vtscan/internal/render"
	"github.com/ibnaleem/vtscan/internal/util"
	"github.com/ibnaleem/vtscan/internal/theme"
)

func main() {

	fmt.Print(theme.Cyan("vtscan") + " -- " + render.Markdown(util.GetRandPhrase()))

	cmd.Execute()

}