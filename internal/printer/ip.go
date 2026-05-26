package printer

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ibnaleem/vtscan/internal/types"
)

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
