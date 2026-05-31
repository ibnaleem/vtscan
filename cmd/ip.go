package cmd

import (
	"encoding/json"
	"fmt"
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
