package cmd

import (

	"os"
	"fmt"
	
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use: "vtscan",
	Short: "Scan files, hashes, URLs, domains, and IPs against VirusTotal",
}

func CheckError(err error) {
	if (err != nil) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func Execute() {

	err := rootCmd.Execute()

	if (err != nil) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

}