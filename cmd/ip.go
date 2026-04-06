package cmd

import (
	"fmt"
	"time"
	"encoding/json"
  "github.com/spf13/cobra"
	"github.com/ibnaleem/vtscan/internal/client"
	"github.com/ibnaleem/vtscan/internal/util"
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

			fmt.Println(string(body))

		}

			return nil

	},
}

func init() {
	rootCmd.AddCommand(ipCmd)
}