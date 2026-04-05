package cmd

import (
	"os"
	
	"github.com/spf13/cobra"
	"github.com/ibnaleem/vtscan/internal/util"
)

var rootCmd = &cobra.Command{
	Use: "vtscan",
	Short: "Scan files, hashes, URLs, domains, and IPs against VirusTotal",
}

func Execute() {

	err := rootCmd.Execute()

	util.CheckError(err)	

}

func init() {
    rootCmd.SilenceErrors = true
		rootCmd.SilenceUsage = true
}

func GetAPIKey() string {
	return os.Getenv("VT_API_KEY")
}