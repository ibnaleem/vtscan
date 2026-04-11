package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ibnaleem/vtscan/internal/client"
	"github.com/ibnaleem/vtscan/internal/util"
	"github.com/spf13/cobra"
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

			body, statusCode, err := client.Get(fmt.Sprintf("domains/%s", domain))
			
			if err != nil {
					return err
			}

			if statusCode != 200 {
				fmt.Printf("vtscan: nothing found for %s\n", domain)
				return nil
			} 
			
			var domainResponse util.DomainResponse 

			err = json.Unmarshal(body, &domainResponse)
			if err != nil {
				fmt.Fprintf(os.Stderr, "vtscan (cmd/domain.go): error unmarshalling JSON for %s: %v\nPlease copy the error message above and raise an issue @ github.com/ibnaleem/vtscan/issues\n", domain, err)
				return nil
			}


			fmt.Println(strings.Repeat("=", 85))
			fmt.Println()

			fmt.Printf("Domain     : %s\n", domain)

			util.PrintDomainResponse(domainResponse)
			
		}

		
		return nil
		
	},
}


func init() {

	rootCmd.AddCommand(domainCmd)
	
}