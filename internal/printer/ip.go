package printer

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ibnaleem/vtscan/internal/render"
	"github.com/ibnaleem/vtscan/internal/theme"
	"github.com/ibnaleem/vtscan/internal/types"
	"github.com/olekukonko/tablewriter"
)

func IPAddressReport(ip string, r types.IPResponse) {
	a := r.Data.Attributes

	lastAnalysisDate     := time.Unix(a.LastAnalysisDate, 0).Format("2006-01-02 15:04:05")
	whoisDate            := time.Unix(a.WhoisDate, 0).Format("2006-01-02 15:04:05")
	lastModificationDate := time.Unix(a.LastModificationDate, 0).Format("2006-01-02 15:04:05")

	fmt.Println(strings.Repeat("=", 85))
	fmt.Println()

	fmt.Printf("IP: %s\n", ip)
	fmt.Printf("Last Modification Date: %s\n", lastModificationDate)
	fmt.Printf("Reputation: %d\n", a.Reputation)

	if len(a.Tags) == 0 {
		fmt.Println("Tags: None")
	} else {
		fmt.Printf("Tags: %s\n", strings.Join(a.Tags, ", "))
	}
	fmt.Println()

	fmt.Printf("Last Analysis: %s\n", lastAnalysisDate)
	fmt.Printf("  Malicious:  %s\n", theme.Red(fmt.Sprintf("%d", a.LastAnalysisStats.Malicious)))
	fmt.Printf("  Suspicious: %s\n", theme.Yellow(fmt.Sprintf("%d", a.LastAnalysisStats.Suspicious)))
	fmt.Printf("  Harmless:   %s\n", theme.Green(fmt.Sprintf("%d", a.LastAnalysisStats.Harmless)))
	fmt.Printf("  Undetected: %s\n", theme.Gray(fmt.Sprintf("%d", a.LastAnalysisStats.Undetected)))
	fmt.Printf("  Timeout:    %s\n", theme.Red(fmt.Sprintf("%d", a.LastAnalysisStats.Timeout)))
	fmt.Println()

	fmt.Println("Community Votes:")
	fmt.Printf("  Harmless:  %s\n", theme.Green(fmt.Sprintf("%d", a.TotalVotes.Harmless)))
	fmt.Printf("  Malicious: %s\n", theme.Red(fmt.Sprintf("%d", a.TotalVotes.Malicious)))
	fmt.Println()

	fmt.Printf("WHOIS Date: %s\n", whoisDate)
	fmt.Println(render.Markdown(fmt.Sprintf("```%s```", a.Whois)))

	table := tablewriter.NewWriter(os.Stdout)
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
	fmt.Println()
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
