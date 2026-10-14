package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/ibnaleem/vtscan/internal/client"
)

// notFoundMsg tells the user VirusTotal has no report yet and how to request one.
// kind is the vtscan subcommand ("ip" or "domain").
func notFoundMsg(kind, target string) string {
	return fmt.Sprintf("vtscan: VirusTotal has no report for %s yet\n  → ask VirusTotal to analyse it:  vtscan %s rescan %s\n", target, kind, target)
}

func rescanQueuedMsg(kind, target, id string) string {
	return fmt.Sprintf("vtscan: ✓ rescan queued for %s (analysis ID: %s)\n  → results usually take a few minutes; check back with:  vtscan %s %s\n", target, id, kind, target)
}

// rescan queues a VirusTotal re-analysis of target in collection
// ("ip_addresses" or "domains") and returns the analysis ID.
func rescan(c *client.Client, collection, target string) (string, error) {
	body, statusCode, err := c.Post(fmt.Sprintf("%s/%s/analyse", collection, url.PathEscape(target)))
	if err != nil {
		return "", err
	}
	if statusCode != 200 {
		return "", fmt.Errorf("vtscan: rescan failed for %s (HTTP %d)", target, statusCode)
	}

	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("vtscan: error unmarshalling rescan response for %s: %w", target, err)
	}
	return resp.Data.ID, nil
}
