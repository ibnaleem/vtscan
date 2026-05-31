package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ibnaleem/vtscan/internal/client"
	"github.com/ibnaleem/vtscan/internal/printer"
	"github.com/ibnaleem/vtscan/internal/render"
	"github.com/ibnaleem/vtscan/internal/theme"
	"github.com/ibnaleem/vtscan/internal/types"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

var ipCmd = &cobra.Command{
	Use:   "ip <address>",
	Short: "Get an IP address report",
	RunE: func(cmd *cobra.Command, args []string) error {

		if len(args) == 0 {
			return fmt.Errorf("\nvtscan: missing IP address argument in command ip.\n\nUsage:\n  vtscan ip <ip address>\n\nFor multiple IP addresses:\n  vtscan ip <ip address 1> <ip address 2> <ip address 3> etc.")
		}

		apiKey := GetAPIKey()

		if apiKey == "" {
			return fmt.Errorf("vtscan: missing VT_API_KEY in environmental variables. Please see the README.md @ github.com/ibnaleem/vtscan to configure your API key")
		}

		c := client.NewClient(apiKey)

		for _, ip := range args {
			body, statusCode, err := c.Get(fmt.Sprintf("ip_addresses/%s", ip))
			if err != nil {
				return err
			}
			if statusCode != 200 {
				fmt.Printf("vtscan: nothing found for %s\n", ip)
				return nil
			}

			var ipResponse types.IPResponse
			if err = json.Unmarshal(body, &ipResponse); err != nil {
				fmt.Fprintf(os.Stderr, "vtscan (cmd/ip.go): error unmarshalling JSON for %s: %v\nPlease copy the error message above and raise an issue @ github.com/ibnaleem/vtscan/issues\n", ip, err)
				return nil
			}

			lastAnalysisDate     := time.Unix(ipResponse.Data.Attributes.LastAnalysisDate, 0).Format("2006-01-02 15:04:05")
			whoisDate            := time.Unix(ipResponse.Data.Attributes.WhoisDate, 0).Format("2006-01-02 15:04:05")
			lastModificationDate := time.Unix(ipResponse.Data.Attributes.LastModificationDate, 0).Format("2006-01-02 15:04:05")

			fmt.Println(strings.Repeat("=", 85))
			fmt.Println()

			fmt.Printf("IP: %s\n", ip)
			fmt.Printf("Last Modification Date: %s\n", lastModificationDate)
			fmt.Printf("Reputation: %d\n", ipResponse.Data.Attributes.Reputation)

			if len(ipResponse.Data.Attributes.Tags) == 0 {
				fmt.Println("Tags: None")
			} else {
				fmt.Printf("Tags: %s\n", strings.Join(ipResponse.Data.Attributes.Tags, ", "))
			}
			fmt.Println()

			fmt.Printf("Last Analysis: %s\n", lastAnalysisDate)
			fmt.Printf("  Malicious:  %s\n", theme.Red(fmt.Sprintf("%d", ipResponse.Data.Attributes.LastAnalysisStats.Malicious)))
			fmt.Printf("  Suspicious: %s\n", theme.Yellow(fmt.Sprintf("%d", ipResponse.Data.Attributes.LastAnalysisStats.Suspicious)))
			fmt.Printf("  Harmless:   %s\n", theme.Green(fmt.Sprintf("%d", ipResponse.Data.Attributes.LastAnalysisStats.Harmless)))
			fmt.Printf("  Undetected: %s\n", theme.Gray(fmt.Sprintf("%d", ipResponse.Data.Attributes.LastAnalysisStats.Undetected)))
			fmt.Printf("  Timeout:    %s\n", theme.Red(fmt.Sprintf("%d", ipResponse.Data.Attributes.LastAnalysisStats.Timeout)))
			fmt.Println()

			fmt.Println("Community Votes:")
			fmt.Printf("  Harmless:  %s\n", theme.Green(fmt.Sprintf("%d", ipResponse.Data.Attributes.TotalVotes.Harmless)))
			fmt.Printf("  Malicious: %s\n", theme.Red(fmt.Sprintf("%d", ipResponse.Data.Attributes.TotalVotes.Malicious)))
			fmt.Println()

			fmt.Printf("WHOIS Date: %s\n", whoisDate)
			fmt.Println(render.Markdown(fmt.Sprintf("```%s```", ipResponse.Data.Attributes.Whois)))
			table := tablewriter.NewWriter(os.Stdout)
			table.Header([]string{"Engine", "Method", "Category", "Result"})

			for _, entry := range ipResponse.Data.Attributes.LastAnalysisResults {
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

		return nil
	},
}

var ipCommentsCmd = &cobra.Command{
	Use:     "comments <ip>",
	Aliases: []string{"comment"},
	Short:   "Get comments on an IP address",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("vtscan: missing IP address argument\n\nUsage:\n  vtscan ip comments <ip address>")
		}

		apiKey := GetAPIKey()
		if apiKey == "" {
			return fmt.Errorf("vtscan: missing VT_API_KEY in environmental variables. Please see the README.md @ github.com/ibnaleem/vtscan to configure your API key")
		}

		c := client.NewClient(apiKey)

		for _, ip := range args {
			body, statusCode, err := c.Get(fmt.Sprintf("ip_addresses/%s/comments?relationships=author", ip))
			if err != nil {
				return err
			}
			if statusCode != 200 {
				fmt.Printf("vtscan: no comments found for %s\n", ip)
				continue
			}

			var resp types.IPCommentsResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				fmt.Fprintf(os.Stderr, "vtscan (cmd/ip.go): error unmarshalling comments for %s: %v\nPlease copy the error message above and raise an issue @ github.com/ibnaleem/vtscan/issues\n", ip, err)
				continue
			}

			printer.IPComments(os.Stdout, ip, resp)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(ipCmd)
	ipCmd.AddCommand(ipCommentsCmd)
}
