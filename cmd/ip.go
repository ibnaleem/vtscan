package cmd

import (
	"os"
	"fmt"
	"time"
	"strings"
	"encoding/json"

  "github.com/spf13/cobra"
	"github.com/ibnaleem/vtscan/internal/client"
	"github.com/ibnaleem/vtscan/internal/util"
	"github.com/olekukonko/tablewriter"
)


var ipCmd = &cobra.Command{
	Use: "ip <address>",
	Short: "Get an IP address report (returns JSON)",
	RunE: func(cmd *cobra.Command, args []string) error {

		if len(args) == 0 {
			return fmt.Errorf("\nvtscan: missing IP address argument in command ip.\n\nUsage:\n  vtscan ip <ip address>\n\nFor multiple IP addresses:\n  vtscan ip <ip address 1> <ip address 2> <ip address 3> etc.")
		}

		apiKey := GetAPIKey()

		if apiKey == "" {
			return fmt.Errorf("vtscan: missing VT_API_KEY in environmental variables. Please see the README.md @ github.com/ibnaleem/vtscan to configure your API key")
		}
		
		client := client.NewClient(apiKey)
		
		for _, ip := range args {
			
		  body, statusCode, err := client.Get(fmt.Sprintf("ip_addresses/%s", ip))
			
			if err != nil {
					return err
			}

			if statusCode != 200 {
				fmt.Printf("vtscan: nothing found for %s\n", ip)
				return nil
			}

			var ipResponse util.IPResponse

			err = json.Unmarshal(body, &ipResponse)

			if err != nil {
				fmt.Println("vtscan: error unmarshalling response in cmd/ip.go")
				return err
			}

			lastAnalysisDate := time.Unix(ipResponse.Data.Attributes.LastAnalysisDate, 0).Format("2006-01-02 15:04:05")
			whoisDate := time.Unix(ipResponse.Data.Attributes.WhoisDate, 0).Format("2006-01-02 15:04:05")
			lastModificationDate :=  time.Unix(ipResponse.Data.Attributes.LastModificationDate, 0).Format("2006-01-02 15:04:05")

			fmt.Println(strings.Repeat("=", 85))
			fmt.Println()

			fmt.Printf("IP: %s\n", ip)
			fmt.Printf("Last Modification Date: %s\n", lastModificationDate)
			fmt.Printf("Reputation: %d\n", ipResponse.Data.Attributes.Reputation)
			fmt.Printf("Tags: %s\n", strings.Join(ipResponse.Data.Attributes.Tags, ", "))

			fmt.Println()

			fmt.Printf("Last Analysis: %s\n", lastAnalysisDate)
			fmt.Printf("  Malicious:  " + util.DarkTheme.Red + "%d\n" + util.DarkTheme.Reset, ipResponse.Data.Attributes.LastAnalysisStats.Malicious)
			fmt.Printf("  Suspicious: " + util.DarkTheme.Yellow + "%d\n" + util.DarkTheme.Reset, ipResponse.Data.Attributes.LastAnalysisStats.Suspicious)
			fmt.Printf("  Harmless:   " + util.DarkTheme.Green + "%d\n" + util.DarkTheme.Reset, ipResponse.Data.Attributes.LastAnalysisStats.Harmless)
			fmt.Printf("  Undetected: " + util.DarkTheme.Gray + "%d\n" + util.DarkTheme.Reset, ipResponse.Data.Attributes.LastAnalysisStats.Undetected)
			fmt.Printf("  Timeout:    " + util.DarkTheme.Red + "%d\n" + util.DarkTheme.Reset, ipResponse.Data.Attributes.LastAnalysisStats.Timeout)

			fmt.Println()

			fmt.Println("Community Votes:")
			fmt.Printf("  Harmless:  " +  util.DarkTheme.Green + "%d\n" + util.DarkTheme.Reset, ipResponse.Data.Attributes.TotalVotes.Harmless)
			fmt.Printf("  Malicious: " + util.DarkTheme.Red + "%d\n" + util.DarkTheme.Reset, ipResponse.Data.Attributes.TotalVotes.Malicious)

			fmt.Println()

			fmt.Printf("WHOIS Date: %s\n", whoisDate)
			fmt.Printf("%s\n", ipResponse.Data.Attributes.Whois)

			fmt.Println()

			fmt.Println("Engine Results:")

			table := tablewriter.NewWriter(os.Stdout)

			table.Header([]string{"Engine", "Method", "Category", "Result"})

			var colourCodedCategory string
			var colourCodedResult string

			for _, entry := range ipResponse.Data.Attributes.LastAnalysisResults {
				if entry.Result == "clean" {
					colourCodedCategory = util.DarkTheme.Green + entry.Category + util.DarkTheme.Reset
					colourCodedResult   = util.DarkTheme.Green + entry.Result + util.DarkTheme.Reset
				} else if entry.Result == "malicious" {
					colourCodedCategory = util.DarkTheme.Red + entry.Category + util.DarkTheme.Reset
					colourCodedResult   = util.DarkTheme.Red + entry.Result + util.DarkTheme.Reset
				} else if entry.Result == "unrated" {
					colourCodedCategory = util.DarkTheme.Gray + entry.Category + util.DarkTheme.Reset
					colourCodedResult   = util.DarkTheme.Gray + entry.Result + util.DarkTheme.Reset
				} else {
					colourCodedCategory = entry.Category
					colourCodedResult = entry.Result
				}
				
				table.Append([]string{entry.EngineName, entry.Method, colourCodedCategory, colourCodedResult})

			}

			table.Render()
		}

			return nil

	},
}

func init() {
	rootCmd.AddCommand(ipCmd)
}