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

var domainCmd = &cobra.Command{
	Use:   "domain <domain>",
	Short: "Get a domain report (returns JSON)",
	RunE: func(cmd *cobra.Command, args []string) error {

		if len(args) == 0 {
			return fmt.Errorf("\nvtscan: missing domain argument in command domain.\n\nUsage:\n  vtscan domain <domain>\n\nFor multiple domains:\n  vtscan domain <domain 1> <domain 2> <domain 3> etc.")
		}

		apiKey := GetAPIKey()

		if apiKey == "" {
			return fmt.Errorf("vtscan: missing VT_API_KEY in environmental variables. Please see the README.md @ github.com/ibnaleem/vtscan to configure your API key")
		}

		c := client.NewClient(apiKey)

		for _, domain := range args {
			body, statusCode, err := c.Get(fmt.Sprintf("domains/%s", domain))
			if err != nil {
				return err
			}
			if statusCode != 200 {
				fmt.Printf("vtscan: nothing found for %s\n", domain)
				return nil
			}

			var domainResponse types.DomainResponse
			if err = json.Unmarshal(body, &domainResponse); err != nil {
				fmt.Fprintf(os.Stderr, "vtscan (cmd/domain.go): error unmarshalling JSON for %s: %v\nPlease copy the error message above and raise an issue @ github.com/ibnaleem/vtscan/issues\n", domain, err)
				return nil
			}

			printer.DomainResponse(domain, domainResponse)
		}

		return nil
	},
}

var domainCommentsCmd = &cobra.Command{
	Use:     "comments <domain>",
	Aliases: []string{"comment"},
	Short:   "Get comments on a domain",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("vtscan: missing domain argument\n\nUsage:\n  vtscan domain comments <domain>")
		}

		apiKey := GetAPIKey()
		if apiKey == "" {
			return fmt.Errorf("vtscan: missing VT_API_KEY in environmental variables. Please see the README.md @ github.com/ibnaleem/vtscan to configure your API key")
		}

		c := client.NewClient(apiKey)

		for _, domain := range args {
			var allComments []types.IPComment
			cursor := ""

			for {
				endpoint := fmt.Sprintf("domains/%s/comments?relationships=author", domain)
				if cursor != "" {
					endpoint += "&cursor=" + url.QueryEscape(cursor)
				}

				body, statusCode, err := c.Get(endpoint)
				if err != nil {
					return err
				}
				if statusCode != 200 {
					if len(allComments) == 0 {
						fmt.Printf("vtscan: no comments found for %s\n", domain)
					}
					break
				}

				var resp types.IPCommentsResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					fmt.Fprintf(os.Stderr, "vtscan (cmd/domain.go): error unmarshalling comments for %s: %v\nPlease copy the error message above and raise an issue @ github.com/ibnaleem/vtscan/issues\n", domain, err)
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
				printer.DomainComments(os.Stdout, domain, combined)
			}
		}

		return nil
	},
}

var domainVotesCmd = &cobra.Command{
	Use:     "votes <domain>",
	Aliases: []string{"vote"},
	Short:   "Get votes on a domain",
	RunE: func(cmd *cobra.Command, args []string) error {

		if len(args) == 0 {
			return fmt.Errorf("vtscan: missing domain argument\n\nUsage:\n  vtscan domain votes <domain>")
		}

		apiKey := GetAPIKey()

		if apiKey == "" {
			return fmt.Errorf("vtscan: missing VT_API_KEY in environmental variables. Please read README.md @ github.com/ibnaleem/vtscan to configure your API key")
		}

		c := client.NewClient(apiKey)

		const maxVotePages = 10

		for _, domain := range args {
			var allVotes []types.IPVote
			cursor := ""
			truncated := false

			for page := 0; ; page++ {
				if page >= maxVotePages {
					truncated = true
					break
				}

				endpoint := fmt.Sprintf("domains/%s/votes?limit=40", domain)
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

				var resp types.IPVotesResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					fmt.Fprintf(os.Stderr, "vtscan (cmd/domain.go): error unmarshalling votes for %s: %v\nPlease copy the error message above and raise an issue @ github.com/ibnaleem/vtscan/issues\n", domain, err)
					break
				}

				allVotes = append(allVotes, resp.Data...)

				if resp.Meta.Cursor == "" {
					break
				}
				cursor = resp.Meta.Cursor
			}

			if len(allVotes) == 0 {
				fmt.Printf("vtscan: no votes found for %s\n", domain)
				continue
			}

			printer.DomainVotes(os.Stdout, domain, types.IPVotesResponse{
				Data: allVotes,
				Meta: types.IPVotesMeta{Count: len(allVotes)},
			})

			if truncated {
				fmt.Printf("vtscan: page cap reached; showing the first %d votes for %s (more exist)\n", len(allVotes), domain)
			}
		}

		return nil
	},
}

var domainRelationshipsCmd = &cobra.Command{
	Use:     "relationships <domain> <relationship>",
	Aliases: []string{"related", "objects"},
	Short:   "Get objects related to a domain",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("vtscan: missing arguments\n\nUsage:\n  vtscan domain relationships <domain> <relationship>\n\nRelationships: caa_records, cname_records, comments, communicating_files, downloaded_files, graphs, historical_ssl_certificates, historical_whois, immediate_parent, mx_records, ns_records, parent, referrer_files, related_comments, related_references, related_threat_actors, resolutions, soa_records, siblings, subdomains, urls, user_votes")
		}

		apiKey := GetAPIKey()
		if apiKey == "" {
			return fmt.Errorf("vtscan: missing VT_API_KEY in environmental variables. Please see the README.md @ github.com/ibnaleem/vtscan to configure your API key")
		}

		domain := args[0]
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
			endpoint := fmt.Sprintf("domains/%s/%s?limit=40", domain, relationship)
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

			objects, meta, err := types.DecodeRelationshipsResponse(body)
			if err != nil {
				fmt.Fprintf(os.Stderr, "vtscan (cmd/domain.go): error unmarshalling relationships for %s: %v\nPlease copy the error message above and raise an issue @ github.com/ibnaleem/vtscan/issues\n", domain, err)
				break
			}

			allObjects = append(allObjects, objects...)

			if meta.Cursor == "" {
				break
			}
			cursor = meta.Cursor
		}

		if len(allObjects) > 0 {
			printer.DomainRelationships(os.Stdout, domain, relationship, allObjects)
			if truncated {
				fmt.Printf("vtscan: page cap reached; showing first %d objects (relationship has more)\n", len(allObjects))
			}
		} else {
			fmt.Printf("vtscan: no %s found for %s\n", relationship, domain)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(domainCmd)
	domainCmd.AddCommand(domainCommentsCmd)
	domainCmd.AddCommand(domainVotesCmd)
	domainCmd.AddCommand(domainRelationshipsCmd)
}
