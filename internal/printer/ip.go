package printer

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/ibnaleem/vtscan/internal/render"
	"github.com/ibnaleem/vtscan/internal/theme"
	"github.com/ibnaleem/vtscan/internal/tui"
	"github.com/ibnaleem/vtscan/internal/types"
	"github.com/olekukonko/tablewriter"
)

var (
	ipHeaderStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86")).PaddingLeft(2)
	ipSectionStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99")).PaddingLeft(2)
	ipLabelStyle   = lipgloss.NewStyle().Width(22).Foreground(lipgloss.Color("245")).PaddingLeft(4)
)

func IPAddressContent(ip string, r types.IPResponse) string {
	a := r.Data.Attributes
	var b strings.Builder

	lastAnalysisDate     := time.Unix(a.LastAnalysisDate, 0).Format("2006-01-02 15:04:05")
	whoisDate            := time.Unix(a.WhoisDate, 0).Format("2006-01-02 15:04:05")
	lastModificationDate := time.Unix(a.LastModificationDate, 0).Format("2006-01-02 15:04:05")

	b.WriteString("\n")
	b.WriteString(ipHeaderStyle.Render(ip) + "\n\n")

	b.WriteString(ipLabelStyle.Render("Modified") + lastModificationDate + "\n")
	b.WriteString(ipLabelStyle.Render("Reputation") + fmt.Sprintf("%d", a.Reputation) + "\n")
	if len(a.Tags) == 0 {
		b.WriteString(ipLabelStyle.Render("Tags") + "None\n")
	} else {
		b.WriteString(ipLabelStyle.Render("Tags") + strings.Join(a.Tags, ", ") + "\n")
	}

	b.WriteString("\n" + ipSectionStyle.Render("── Analysis") + "\n\n")
	b.WriteString(ipLabelStyle.Render("Date") + lastAnalysisDate + "\n")
	b.WriteString(ipLabelStyle.Render("Malicious") + theme.Red(fmt.Sprintf("%d", a.LastAnalysisStats.Malicious)) + "\n")
	b.WriteString(ipLabelStyle.Render("Suspicious") + theme.Yellow(fmt.Sprintf("%d", a.LastAnalysisStats.Suspicious)) + "\n")
	b.WriteString(ipLabelStyle.Render("Harmless") + theme.Green(fmt.Sprintf("%d", a.LastAnalysisStats.Harmless)) + "\n")
	b.WriteString(ipLabelStyle.Render("Undetected") + theme.Gray(fmt.Sprintf("%d", a.LastAnalysisStats.Undetected)) + "\n")
	b.WriteString(ipLabelStyle.Render("Timeout") + theme.Red(fmt.Sprintf("%d", a.LastAnalysisStats.Timeout)) + "\n")

	b.WriteString("\n" + ipSectionStyle.Render("── Community Votes") + "\n\n")
	b.WriteString(ipLabelStyle.Render("Harmless") + theme.Green(fmt.Sprintf("%d", a.TotalVotes.Harmless)) + "\n")
	b.WriteString(ipLabelStyle.Render("Malicious") + theme.Red(fmt.Sprintf("%d", a.TotalVotes.Malicious)) + "\n")

	b.WriteString("\n" + ipSectionStyle.Render("── WHOIS") + "\n\n")
	b.WriteString(ipLabelStyle.Render("Date") + whoisDate + "\n")
	b.WriteString(render.Markdown(fmt.Sprintf("```\n%s\n```", a.Whois)))

	b.WriteString(ipSectionStyle.Render("── Engine Results") + "\n\n")
	var tableBuf bytes.Buffer
	table := tablewriter.NewWriter(&tableBuf)
	table.Header([]string{"Engine", "Method", "Category", "Result"})
	for _, entry := range a.LastAnalysisResults {
		var cat, res string
		switch entry.Result {
		case "clean":
			cat = theme.Green(entry.Category)
			res = theme.Green(entry.Result)
		case "malicious":
			cat = theme.Red(entry.Category)
			res = theme.Red(entry.Result)
		case "unrated":
			cat = theme.Gray(entry.Category)
			res = theme.Gray(entry.Result)
		default:
			cat = entry.Category
			res = entry.Result
		}
		table.Append([]string{entry.EngineName, entry.Method, cat, res})
	}
	table.Render()
	b.WriteString(tableBuf.String())
	b.WriteString("\n")

	return b.String()
}

func IPAddressReport(ip string, r types.IPResponse) {
	content := IPAddressContent(ip, r)
	if err := tui.Render(content); err != nil {
		fmt.Print(content)
	}
}

func IPComments(w io.Writer, ip string, resp types.IPCommentsResponse) {
	fmt.Fprintf(w, "Comments for %s (%d on this page)\n\n", ip, resp.Meta.Count)

	if len(resp.Data) == 0 {
		fmt.Fprintln(w, "No comments found.")
		return
	}

	for i, c := range resp.Data {
		date   := time.Unix(c.Attributes.Date, 0).Format("2006-01-02 15:04:05")
		author := c.Relationships.Author.Data.ID
		if author == "" {
			author = "unknown"
		}
		fmt.Fprintf(w, "[%d] %s  by %s\n", i+1, date, author)
		if len(c.Attributes.Tags) > 0 {
			fmt.Fprintf(w, "    Tags: %s\n", strings.Join(c.Attributes.Tags, ", "))
		}
		fmt.Fprintf(w, "    Votes: +%d / -%d (abuse: %d)\n", c.Attributes.Votes.Positive, c.Attributes.Votes.Negative, c.Attributes.Votes.Abuse)
		fmt.Fprintf(w, "    %s\n\n", c.Attributes.Text)
	}

	if resp.Meta.Cursor != "" {
		fmt.Fprintln(w, "Note: more comments exist. Pagination not yet implemented.")
	}
}
