package main

import (
	"fmt"

	"github.com/ibnaleem/vtscan/cmd"
	"github.com/ibnaleem/vtscan/internal/theme"
	"github.com/ibnaleem/vtscan/internal/util"
)

func main() {

	fmt.Println(theme.Bold("vtscan") + " - " + util.GetRandPhrase())

	cmd.Execute()

}