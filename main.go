package main

import (
	"fmt"
	"strings"

	"github.com/ibnaleem/vtscan/cmd"
	"github.com/ibnaleem/vtscan/internal/render"
	"github.com/ibnaleem/vtscan/internal/util"
)

func main() {

	vtscanTitle := strings.TrimSpace(render.Markdown("**vtscan**"))
	phraseRender := strings.TrimSpace(render.Markdown(util.GetRandPhrase()))

	fmt.Println(vtscanTitle + " - " + phraseRender)

	cmd.Execute()

}