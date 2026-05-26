package main

import (
	"fmt"

	"github.com/ibnaleem/vtscan/cmd"
	"github.com/ibnaleem/vtscan/internal/theme"
	"github.com/ibnaleem/vtscan/internal/util"
)

func main() {

	fmt.Println()
	fmt.Println(theme.Bold(theme.Cyan("vtscan")) + theme.Gray(" · ") + theme.Gray(util.GetRandPhrase()))
	fmt.Println()

	cmd.Execute()

}