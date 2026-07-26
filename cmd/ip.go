package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/ibnaleem/vtscan/internal/client"
	"github.com/ibnaleem/vtscan/internal/printer"
	"github.com/ibnaleem/vtscan/internal/types"
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

			printer.IPAddressReport(ip, ipResponse)
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
			var allComments []types.IPComment
			cursor := ""

			for {
				endpoint := fmt.Sprintf("ip_addresses/%s/comments?relationships=author", ip)
				if cursor != "" {
					endpoint += "&cursor=" + url.QueryEscape(cursor)
				}

				body, statusCode, err := c.Get(endpoint)
				if err != nil {
					return err
				}
				if statusCode != 200 {
					if len(allComments) == 0 {
						fmt.Printf("vtscan: no comments found for %s\n", ip)
					}
					break
				}

				var resp types.IPCommentsResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					fmt.Fprintf(os.Stderr, "vtscan (cmd/ip.go): error unmarshalling comments for %s: %v\nPlease copy the error message above and raise an issue @ github.com/ibnaleem/vtscan/issues\n", ip, err)
					break
				}

				allComments = append(allComments, resp.Data...)

				if resp.Meta.Cursor == "" {
					break
				}
				cursor = resp.Meta.Cursor
			}

			if len(allComments) > 0 {
				combined := types.IPCommentsResponse{
					Data: allComments,
					Meta: types.IPCommentsMeta{Count: len(allComments)},
				}
				printer.IPComments(os.Stdout, ip, combined)
			}
		}

		return nil
	},
}

var ipVotesCmd = &cobra.Command{
	Use:     "votes <ip>",
	Aliases: []string{"vote"},
	Short:   "Get votes on an IP address",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("vtscan: missing IP address argument\n\nUsage:\n  vtscan ip votes <ip address>")
		}

		apiKey := GetAPIKey()
		if apiKey == "" {
			return fmt.Errorf("vtscan: missing VT_API_KEY in environmental variables. Please see the README.md @ github.com/ibnaleem/vtscan to configure your API key")
		}

		c := client.NewClient(apiKey)

		for _, ip := range args {
			var allVotes []types.IPVote
			cursor := ""

			for {
				endpoint := fmt.Sprintf("ip_addresses/%s/votes", ip)
				if cursor != "" {
					endpoint += "?cursor=" + url.QueryEscape(cursor)
				}

				body, statusCode, err := c.Get(endpoint)
				if err != nil {
					return err
				}
				if statusCode != 200 {
					if len(allVotes) == 0 {
						fmt.Printf("vtscan: no votes found for %s\n", ip)
					}
					break
				}

				var resp types.IPVotesResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					fmt.Fprintf(os.Stderr, "vtscan (cmd/ip.go): error unmarshalling votes for %s: %v\nPlease copy the error message above and raise an issue @ github.com/ibnaleem/vtscan/issues\n", ip, err)
					break
				}

				allVotes = append(allVotes, resp.Data...)

				if resp.Meta.Cursor == "" {
					break
				}
				cursor = resp.Meta.Cursor
			}

			if len(allVotes) > 0 {
				combined := types.IPVotesResponse{
					Data: allVotes,
					Meta: types.IPVotesMeta{Count: len(allVotes)},
				}
				printer.IPVotes(os.Stdout, ip, combined)
			}
		}

		return nil
	},
}

var ipRelationshipsCmd = &cobra.Command{
	Use:     "relationships <ip> <relationship>",
	Aliases: []string{"related", "objects"},
	Short:   "Get objects related to an IP address",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("vtscan: missing arguments\n\nUsage:\n  vtscan ip relationships <ip address> <relationship>\n\nRelationships: communicating_files, downloaded_files, graphs, historical_ssl_certificates, historical_whois, referrer_files, related_comments, related_references, related_threat_actors, resolutions, urls")
		}

		apiKey := GetAPIKey()
		if apiKey == "" {
			return fmt.Errorf("vtscan: missing VT_API_KEY in environmental variables. Please see the README.md @ github.com/ibnaleem/vtscan to configure your API key")
		}

		ip := args[0]
		relationship := args[1]

		c := client.NewClient(apiKey)

		const maxRelationshipPages = 10

		var allObjects []types.IPRelatedObject
		cursor := ""
		truncated := false

		for page := 0; ; page++ {
			if page >= maxRelationshipPages {
				truncated = true
				break
			}
			endpoint := fmt.Sprintf("ip_addresses/%s/%s?limit=40", ip, relationship)
			if cursor != "" {
				endpoint += "&cursor=" + url.QueryEscape(cursor)
			}

			body, statusCode, err := c.Get(endpoint)
			if err != nil {
				return err
			}
			if statusCode != 200 {
				break
			}

			var resp types.IPRelationshipsResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				fmt.Fprintf(os.Stderr, "vtscan (cmd/ip.go): error unmarshalling relationships for %s: %v\nPlease copy the error message above and raise an issue @ github.com/ibnaleem/vtscan/issues\n", ip, err)
				break
			}

			var page []types.IPRelatedObject
			if err := json.Unmarshal(resp.Data, &page); err != nil {
				var single types.IPRelatedObject
				if err := json.Unmarshal(resp.Data, &single); err != nil {
					break
				}
				if single.ID != "" {
					page = append(page, single)
				}
			}

			allObjects = append(allObjects, page...)

			if resp.Meta.Cursor == "" {
				break
			}
			cursor = resp.Meta.Cursor
		}

		if len(allObjects) > 0 {
			printer.IPRelationships(os.Stdout, ip, relationship, allObjects)
			if truncated {
				fmt.Printf("vtscan: page cap reached; showing first %d objects (relationship has more)\n", len(allObjects))
			}
		} else {
			fmt.Printf("vtscan: no %s found for %s\n", relationship, ip)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(ipCmd)
	ipCmd.AddCommand(ipCommentsCmd)
	ipCmd.AddCommand(ipVotesCmd)
	ipCmd.AddCommand(ipRelationshipsCmd)
}
