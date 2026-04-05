package cmd

import (
	"fmt"
	
	"github.com/spf13/cobra"
	"github.com/ibnaleem/vtscan/internal/client"
)

var domainCmd = &cobra.Command{
	Use: "domain <domain>",
	Short: "Get a domain report (returns JSON)",
	RunE: func(cmd *cobra.Command, args []string) error {

		if len(args) == 0 {
			return fmt.Errorf("\nvtscan: missing domain argument in command domain.\n\nUsage:\n  vtscan domain <domain>\n\nFor multiple domains:\n  vtscan domain <domain 1> <domain 2> <domain 3> etc.")
		}

		apiKey := GetAPIKey()

		if apiKey == "" {
			return fmt.Errorf("vtscan: missing VT_API_KEY in environmental variables. Please see the README.md @ github.com/ibnaleem/vtscan to configure your API key")
		}
		
		client := client.NewClient(apiKey)

		for _, domain := range args {

			body, err := client.Get(fmt.Sprintf("domains/%s", domain))
			
			if err != nil {
					return err
			}

			fmt.Println(string(body))

		}

		return nil
		
	},
}


func init() {

	rootCmd.AddCommand(domainCmd)
	
}