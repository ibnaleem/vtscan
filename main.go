package main

import (
	"fmt"
	"time"

	"github.com/ibnaleem/vtscan/cmd"
	"github.com/ibnaleem/vtscan/internal/theme"
	"github.com/ibnaleem/vtscan/internal/util"
)

func main() {

	fmt.Println()
	fmt.Println(theme.Bold(theme.Cyan("vtscan")) + theme.Gray(" · ") + theme.Gray(util.GetRandTitlePhrase()))
	fmt.Println()

	start := time.Now()
	cmd.Execute()
	elapsed := time.Since(start)

	fmt.Println(theme.Gray("✦ " + util.GetRandEndingPhrase() + " " + elapsed.Round(time.Millisecond).String()))

}