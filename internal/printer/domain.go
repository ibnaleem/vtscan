package printer

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ibnaleem/vtscan/internal/theme"
	"github.com/ibnaleem/vtscan/internal/types"
	"github.com/olekukonko/tablewriter"
)

func DomainResponse(d types.DomainResponse) {
	a := d.Data.Attributes

	creationDate         := time.Unix(a.CreationDate, 0).Format("2006-01-02 15:04:05")
	lastModificationDate := time.Unix(a.LastModificationDate, 0).Format("2006-01-02 15:04:05")
	lastAnalysisDate     := time.Unix(a.LastAnalysisDate, 0).Format("2006-01-02 15:04:05")
	lastDNSRecordsDate   := time.Unix(a.LastDNSRecordsDate, 0).Format("2006-01-02 15:04:05")
	lastHTTPSCertDate    := time.Unix(a.LastHTTPSCertDate, 0).Format("2006-01-02 15:04:05")
	lastUpdateDate       := time.Unix(a.LastUpdateDate, 0).Format("2006-01-02 15:04:05")
	whoisDate            := time.Unix(a.WhoisDate, 0).Format("2006-01-02 15:04:05")

	fmt.Printf("TLD        : %s\n", a.TLD)
	fmt.Printf("Reputation : %d\n", a.Reputation)
	fmt.Printf("JARM       : %s\n", a.JARM)

	if len(a.Tags) == 0 {
		fmt.Println("Tags       : None")
	} else {
		fmt.Printf("Tags        : %s\n", strings.Join(a.Tags, ", "))
	}

	fmt.Println()
	fmt.Println("Dates:")
	fmt.Printf("  Created       : %s\n", creationDate)
	fmt.Printf("  Last Updated  : %s\n", lastUpdateDate)
	fmt.Printf("  Last Analysis : %s\n", lastAnalysisDate)
	fmt.Printf("  Last DNS      : %s\n", lastDNSRecordsDate)
	fmt.Printf("  Last HTTPS    : %s\n", lastHTTPSCertDate)
	fmt.Printf("  Modified      : %s\n", lastModificationDate)
	fmt.Printf("  WHOIS Date    : %s\n", whoisDate)

	fmt.Println()
	fmt.Println("Last Analysis:")
	fmt.Printf("  Malicious  : %s\n", theme.Red(strconv.Itoa(a.LastAnalysisStats.Malicious)))
	fmt.Printf("  Suspicious : %s\n", theme.Yellow(strconv.Itoa(a.LastAnalysisStats.Suspicious)))
	fmt.Printf("  Harmless   : %s\n", theme.Green(strconv.Itoa(a.LastAnalysisStats.Harmless)))
	fmt.Printf("  Undetected : %d\n", a.LastAnalysisStats.Undetected)
	fmt.Printf("  Timeout    : %s\n", theme.Red(strconv.Itoa(a.LastAnalysisStats.Timeout)))

	fmt.Println()
	fmt.Println("Community Votes:")
	fmt.Printf("  Harmless  : %s\n", theme.Green(strconv.Itoa(a.TotalVotes.Harmless)))
	fmt.Printf("  Malicious : %s\n", theme.Red(strconv.Itoa(a.TotalVotes.Malicious)))

	fmt.Println()
	fmt.Println("HTTPS Certificate:")
	fmt.Printf("  Subject           : %s\n", a.LastHTTPSCertificate.Subject.CN)
	fmt.Printf("  Issuer            : %s (%s)\n", a.LastHTTPSCertificate.Issuer.O, a.LastHTTPSCertificate.Issuer.CN)
	fmt.Printf("  Serial            : %s\n", a.LastHTTPSCertificate.SerialNumber)
	fmt.Printf("  Thumbprint        : %s\n", a.LastHTTPSCertificate.Thumbprint)
	fmt.Printf("  Thumbprint SHA256 : %s\n", a.LastHTTPSCertificate.ThumbprintSHA256)
	fmt.Printf("  Version           : %s\n", a.LastHTTPSCertificate.Version)
	fmt.Printf("  Valid From        : %s\n", a.LastHTTPSCertificate.Validity.NotBefore)
	fmt.Printf("  Valid Until       : %s\n", a.LastHTTPSCertificate.Validity.NotAfter)

	fmt.Println()
	fmt.Println("DNS Records:")
	dnsTable := tablewriter.NewTable(os.Stdout)
	dnsTable.Header([]string{"Type", "TTL", "Value"})
	for _, record := range a.LastDNSRecords {
		dnsTable.Append([]string{record.Type, fmt.Sprintf("%d", record.TTL), record.Value})
	}
	dnsTable.Render()

	fmt.Println()
	fmt.Println("RDAP:")
	fmt.Printf("  Handle: %s\n", a.RDAP.Handle)
	fmt.Printf("  Status: %s\n", strings.Join(a.RDAP.Status, ", "))
	fmt.Println("  Nameservers:")
	for _, ns := range a.RDAP.Nameservers {
		fmt.Printf("    - %s\n", ns.LdhName)
	}
	fmt.Println("  Events:")
	for _, event := range a.RDAP.Events {
		fmt.Printf("    - %-35s %s\n", event.EventAction+":", event.EventDate)
	}

	fmt.Println("  Secure DNS:")
	fmt.Printf("    Delegation Signed : %v\n", a.RDAP.SecureDNS.DelegationSigned)
	fmt.Printf("    Zone Signed       : %v\n", a.RDAP.SecureDNS.ZoneSigned)
	if len(a.RDAP.SecureDNS.DSData) > 0 {
		fmt.Println("    DS Data:")
		for _, ds := range a.RDAP.SecureDNS.DSData {
			fmt.Printf("      Algorithm: %d | Digest Type: %d | Key Tag: %d\n", ds.Algorithm, ds.DigestType, ds.KeyTag)
			fmt.Printf("      Digest: %s\n", ds.Digest)
		}
	}

	fmt.Println("  Notices:")
	for _, notice := range a.RDAP.Notices {
		fmt.Printf("    [%s]\n", notice.Title)
		for _, desc := range notice.Description {
			fmt.Printf("      %s\n", desc)
		}
	}

	fmt.Println("  Entities:")
	for _, entity := range a.RDAP.Entities {
		fmt.Printf("    Role: %s\n", strings.Join(entity.Roles, ", "))
		for _, vcard := range entity.VCardArray {
			if vcard.Name == "fn" {
				fmt.Printf("    Name: %s\n", strings.Join(vcard.Values, ", "))
			}
			if vcard.Name == "email" {
				fmt.Printf("    Email: %s\n", strings.Join(vcard.Values, ", "))
			}
			if vcard.Name == "tel" {
				fmt.Printf("    Phone: %s\n", strings.Join(vcard.Values, ", "))
			}
		}
		fmt.Println()
	}

	fmt.Println()
	fmt.Println("WHOIS:")
	fmt.Println(a.Whois)

	fmt.Println()
	fmt.Println("Engine Results:")
	enginesTable := tablewriter.NewTable(os.Stdout)
	enginesTable.Header([]string{"Engine", "Method", "Category", "Result"})

	for _, result := range a.LastAnalysisResults {
		var cat, res string
		switch result.Category {
		case "harmless":
			cat = theme.Green(result.Category)
			res = theme.Green(result.Result)
		case "malicious":
			cat = theme.Red(result.Category)
			res = theme.Red(result.Result)
		default:
			cat = result.Category
			res = result.Result
		}
		enginesTable.Append([]string{result.EngineName, result.Method, cat, res})
	}
	enginesTable.Render()
}
