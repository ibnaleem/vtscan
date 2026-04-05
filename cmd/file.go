package cmd

import (
	"os"
	"fmt"
  "github.com/spf13/cobra"
	"github.com/ibnaleem/vtscan/internal/client"
	"github.com/ibnaleem/vtscan/internal/util"
)

var fileCmd = &cobra.Command{
	Use: "file <hash or path>",
	Short: "Get a file report by either specifying a file path or specifying a MD5, SHA1 or SHA-256 hash",

	RunE: func(cmd *cobra.Command, args []string) error {
		
		if len(args) == 0 {
			return fmt.Errorf("\nvtscan: missing path or hash argument in command file.\n\nUsage:\n  vtscan file <hash or path>\n\nFor multiple paths/hashes:\n  vtscan file <hash 1> <path 1> <hash 2> <path 2> <path 3> etc.")
		}

		apiKey := GetAPIKey()

		if apiKey == "" {
			return fmt.Errorf("vtscan: missing VT_API_KEY in environmental variables. Please see the README.md @ github.com/ibnaleem/vtscan to configure your API key")
		}
		
		client := client.NewClient(apiKey)

		for _, arg := range args {
			if util.CheckHash(arg) {
				body, err := client.Get(fmt.Sprintf("files/%s", arg))

				if err != nil {
					return err
				}

				fmt.Println(string(body))

				return nil

			} else {
				_, err := os.Stat(arg)

				if os.IsNotExist(err) {
					fmt.Printf("vtscan: %s does not exist: skipping...\n", arg)
					continue
				} else {
					hash, err := util.CalculateFileSHA256Hash(arg)

					if err != nil || hash == "" {
						return fmt.Errorf("vtscan: could not hash %s: %v", arg, err)
					}

					body, err := client.Get(fmt.Sprintf("files/%s", hash))

					if err != nil {
						return err
					}

					fmt.Println(string(body))

					return nil

				}

			}
		}
		
		return nil
	},

}

func init() {
	rootCmd.AddCommand(fileCmd)
}