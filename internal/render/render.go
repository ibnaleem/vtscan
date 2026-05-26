package render

import "github.com/charmbracelet/glamour"

func Markdown(md string) string {
	out, err := glamour.Render(md, "auto")
	if err != nil {
		return md
	}
	return out
}
