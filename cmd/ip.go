package cmd

import (
	"fmt"
  "github.com/spf13/cobra"
	"github.com/ibnaleem/vtscan/internal/client"
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
			
			body, err := client.Get(fmt.Sprintf("ip_addresses/%s", ip))
			
			if err != nil {
					return err
			}

			fmt.Println(string(body))

		}

			return nil

	},
}

func init() {
	rootCmd.AddCommand(ipCmd)
}