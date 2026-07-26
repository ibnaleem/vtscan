package printer

import (
	"bytes"
	"encoding/json"
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

	lastAnalysisDate := time.Unix(a.LastAnalysisDate, 0).Format("2006-01-02 15:04:05")
	whoisDate := time.Unix(a.WhoisDate, 0).Format("2006-01-02 15:04:05")
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

func IPCommentsContent(ip string, resp types.IPCommentsResponse) string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(ipHeaderStyle.Render(fmt.Sprintf("Comments for %s", ip)) + "\n")
	b.WriteString(ipSectionStyle.Render(fmt.Sprintf("  %d comment(s)", resp.Meta.Count)) + "\n\n")

	if len(resp.Data) == 0 {
		b.WriteString("  No comments found.\n")
		return b.String()
	}

	for i, c := range resp.Data {
		date := time.Unix(c.Attributes.Date, 0).Format("2006-01-02 15:04:05")
		author := c.Relationships.Author.Data.ID
		if author == "" {
			author = "unknown"
		}

		b.WriteString(ipSectionStyle.Render(fmt.Sprintf("── [%d] %s  by %s", i+1, date, author)) + "\n")

		if len(c.Attributes.Tags) > 0 {
			b.WriteString(ipLabelStyle.Render("Tags") + strings.Join(c.Attributes.Tags, ", ") + "\n")
		}

		b.WriteString(ipLabelStyle.Render("Votes") + fmt.Sprintf("+%d / -%d (abuse: %d)",
			c.Attributes.Votes.Positive, c.Attributes.Votes.Negative, c.Attributes.Votes.Abuse) + "\n")
		b.WriteString("\n    " + c.Attributes.Text + "\n\n")
	}

	return b.String()
}

func IPComments(w io.Writer, ip string, resp types.IPCommentsResponse) {
	content := IPCommentsContent(ip, resp)
	if err := tui.Render(content); err != nil {
		fmt.Fprint(w, content)
	}
}

func IPVotesContent(ip string, resp types.IPVotesResponse) string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(ipHeaderStyle.Render(fmt.Sprintf("Votes for %s", ip)) + "\n")
	b.WriteString(ipSectionStyle.Render(fmt.Sprintf("  %d vote(s)", resp.Meta.Count)) + "\n\n")

	if len(resp.Data) == 0 {
		b.WriteString("  No votes found.\n")
		return b.String()
	}

	var harmless, malicious int
	for _, v := range resp.Data {
		if v.Attributes.Value >= 0 {
			harmless++
		} else {
			malicious++
		}
	}

	b.WriteString(ipLabelStyle.Render("Harmless") + theme.Green(fmt.Sprintf("%d", harmless)) + "\n")
	b.WriteString(ipLabelStyle.Render("Malicious") + theme.Red(fmt.Sprintf("%d", malicious)) + "\n")

	b.WriteString("\n")

	var tableBuf bytes.Buffer
	table := tablewriter.NewWriter(&tableBuf)
	table.Header([]string{"#", "Date", "Verdict", "Value", "Vote ID"})

	for i, v := range resp.Data {
		verdict := v.Attributes.Verdict
		if v.Attributes.Value >= 0 {
			verdict = theme.Green(verdict)
		} else {
			verdict = theme.Red(verdict)
		}

		table.Append([]string{
			fmt.Sprintf("%d", i+1),
			time.Unix(v.Attributes.Date, 0).Format("2006-01-02 15:04:05"),
			verdict,
			fmt.Sprintf("%+d", v.Attributes.Value),
			v.ID,
		})
	}

	table.Render()
	b.WriteString(tableBuf.String())
	b.WriteString("\n")

	return b.String()
}

func IPVotes(w io.Writer, ip string, resp types.IPVotesResponse) {
	content := IPVotesContent(ip, resp)
	if err := tui.Render(content); err != nil {
		fmt.Fprint(w, content)
	}
}

func IPRelationshipsContent(ip, relationship string, objects []types.IPRelatedObject) string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(ipHeaderStyle.Render(fmt.Sprintf("%s for %s", relationship, ip)) + "\n")
	b.WriteString(ipSectionStyle.Render(fmt.Sprintf("  %d object(s)", len(objects))) + "\n\n")

	if len(objects) == 0 {
		b.WriteString("  No related objects found.\n")
		return b.String()
	}

	var tableBuf bytes.Buffer
	table := tablewriter.NewWriter(&tableBuf)
	table.Header([]string{"#", "Type", "ID", "Malicious"})
	for i, o := range objects {
		malicious := theme.Gray("-")
		if len(o.Attributes) > 0 {
			var stats types.RelatedObjectStats
			if err := json.Unmarshal(o.Attributes, &stats); err == nil && stats.LastAnalysisStats != nil {
				if m := stats.LastAnalysisStats.Malicious; m > 0 {
					malicious = theme.Red(fmt.Sprintf("%d", m))
				} else {
					malicious = theme.Green("0")
				}
			}
		}
		table.Append([]string{fmt.Sprintf("%d", i+1), o.Type, o.ID, malicious})
	}
	table.Render()
	b.WriteString(tableBuf.String())
	b.WriteString("\n")

	return b.String()
}

func IPRelationships(w io.Writer, ip, relationship string, objects []types.IPRelatedObject) {
	content := IPRelationshipsContent(ip, relationship, objects)
	if err := tui.Render(content); err != nil {
		fmt.Fprint(w, content)
	}
}
