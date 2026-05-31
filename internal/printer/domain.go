package printer

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/ibnaleem/vtscan/internal/render"
	"github.com/ibnaleem/vtscan/internal/theme"
	"github.com/ibnaleem/vtscan/internal/tui"
	"github.com/ibnaleem/vtscan/internal/types"
	"github.com/olekukonko/tablewriter"
)

var (
	domainHeaderStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86")).PaddingLeft(2)
	domainSectionStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99")).PaddingLeft(2)
	domainLabelStyle   = lipgloss.NewStyle().Width(24).Foreground(lipgloss.Color("245")).PaddingLeft(4)
)

func DomainContent(domain string, d types.DomainResponse) string {
	a := d.Data.Attributes
	var b strings.Builder

	creationDate         := time.Unix(a.CreationDate, 0).Format("2006-01-02 15:04:05")
	lastModificationDate := time.Unix(a.LastModificationDate, 0).Format("2006-01-02 15:04:05")
	lastAnalysisDate     := time.Unix(a.LastAnalysisDate, 0).Format("2006-01-02 15:04:05")
	lastDNSRecordsDate   := time.Unix(a.LastDNSRecordsDate, 0).Format("2006-01-02 15:04:05")
	lastHTTPSCertDate    := time.Unix(a.LastHTTPSCertDate, 0).Format("2006-01-02 15:04:05")
	lastUpdateDate       := time.Unix(a.LastUpdateDate, 0).Format("2006-01-02 15:04:05")
	whoisDate            := time.Unix(a.WhoisDate, 0).Format("2006-01-02 15:04:05")

	b.WriteString("\n")
	if domain != "" {
		b.WriteString(domainHeaderStyle.Render(domain) + "\n\n")
	}

	b.WriteString(domainLabelStyle.Render("TLD") + a.TLD + "\n")
	b.WriteString(domainLabelStyle.Render("Reputation") + fmt.Sprintf("%d", a.Reputation) + "\n")
	b.WriteString(domainLabelStyle.Render("JARM") + a.JARM + "\n")
	if len(a.Tags) == 0 {
		b.WriteString(domainLabelStyle.Render("Tags") + "None\n")
	} else {
		b.WriteString(domainLabelStyle.Render("Tags") + strings.Join(a.Tags, ", ") + "\n")
	}

	b.WriteString("\n" + domainSectionStyle.Render("── Dates") + "\n\n")
	b.WriteString(domainLabelStyle.Render("Created") + creationDate + "\n")
	b.WriteString(domainLabelStyle.Render("Last Updated") + lastUpdateDate + "\n")
	b.WriteString(domainLabelStyle.Render("Last Analysis") + lastAnalysisDate + "\n")
	b.WriteString(domainLabelStyle.Render("Last DNS") + lastDNSRecordsDate + "\n")
	b.WriteString(domainLabelStyle.Render("Last HTTPS") + lastHTTPSCertDate + "\n")
	b.WriteString(domainLabelStyle.Render("Modified") + lastModificationDate + "\n")
	b.WriteString(domainLabelStyle.Render("WHOIS Date") + whoisDate + "\n")

	b.WriteString("\n" + domainSectionStyle.Render("── Last Analysis") + "\n\n")
	b.WriteString(domainLabelStyle.Render("Malicious") + theme.Red(fmt.Sprintf("%d", a.LastAnalysisStats.Malicious)) + "\n")
	b.WriteString(domainLabelStyle.Render("Suspicious") + theme.Yellow(fmt.Sprintf("%d", a.LastAnalysisStats.Suspicious)) + "\n")
	b.WriteString(domainLabelStyle.Render("Harmless") + theme.Green(fmt.Sprintf("%d", a.LastAnalysisStats.Harmless)) + "\n")
	b.WriteString(domainLabelStyle.Render("Undetected") + fmt.Sprintf("%d", a.LastAnalysisStats.Undetected) + "\n")
	b.WriteString(domainLabelStyle.Render("Timeout") + theme.Red(fmt.Sprintf("%d", a.LastAnalysisStats.Timeout)) + "\n")

	b.WriteString("\n" + domainSectionStyle.Render("── Community Votes") + "\n\n")
	b.WriteString(domainLabelStyle.Render("Harmless") + theme.Green(fmt.Sprintf("%d", a.TotalVotes.Harmless)) + "\n")
	b.WriteString(domainLabelStyle.Render("Malicious") + theme.Red(fmt.Sprintf("%d", a.TotalVotes.Malicious)) + "\n")

	b.WriteString("\n" + domainSectionStyle.Render("── HTTPS Certificate") + "\n\n")
	b.WriteString(domainLabelStyle.Render("Subject") + a.LastHTTPSCertificate.Subject.CN + "\n")
	b.WriteString(domainLabelStyle.Render("Issuer") + fmt.Sprintf("%s (%s)", a.LastHTTPSCertificate.Issuer.O, a.LastHTTPSCertificate.Issuer.CN) + "\n")
	b.WriteString(domainLabelStyle.Render("Serial") + a.LastHTTPSCertificate.SerialNumber + "\n")
	b.WriteString(domainLabelStyle.Render("Thumbprint") + a.LastHTTPSCertificate.Thumbprint + "\n")
	b.WriteString(domainLabelStyle.Render("Thumbprint SHA256") + a.LastHTTPSCertificate.ThumbprintSHA256 + "\n")
	b.WriteString(domainLabelStyle.Render("Version") + a.LastHTTPSCertificate.Version + "\n")
	b.WriteString(domainLabelStyle.Render("Valid From") + a.LastHTTPSCertificate.Validity.NotBefore + "\n")
	b.WriteString(domainLabelStyle.Render("Valid Until") + a.LastHTTPSCertificate.Validity.NotAfter + "\n")

	b.WriteString("\n" + domainSectionStyle.Render("── DNS Records") + "\n\n")
	var dnsBuf bytes.Buffer
	dnsTable := tablewriter.NewTable(&dnsBuf)
	dnsTable.Header([]string{"Type", "TTL", "Value"})
	for _, record := range a.LastDNSRecords {
		dnsTable.Append([]string{record.Type, fmt.Sprintf("%d", record.TTL), record.Value})
	}
	dnsTable.Render()
	b.WriteString(dnsBuf.String())

	b.WriteString("\n" + domainSectionStyle.Render("── RDAP") + "\n\n")
	b.WriteString(domainLabelStyle.Render("Handle") + a.RDAP.Handle + "\n")
	b.WriteString(domainLabelStyle.Render("Status") + strings.Join(a.RDAP.Status, ", ") + "\n")
	b.WriteString("    Nameservers:\n")
	for _, ns := range a.RDAP.Nameservers {
		b.WriteString(fmt.Sprintf("      - %s\n", ns.LdhName))
	}
	b.WriteString("    Events:\n")
	for _, event := range a.RDAP.Events {
		b.WriteString(fmt.Sprintf("      - %-35s %s\n", event.EventAction+":", event.EventDate))
	}
	b.WriteString(fmt.Sprintf("    Delegation Signed : %v\n", a.RDAP.SecureDNS.DelegationSigned))
	b.WriteString(fmt.Sprintf("    Zone Signed       : %v\n", a.RDAP.SecureDNS.ZoneSigned))
	if len(a.RDAP.SecureDNS.DSData) > 0 {
		b.WriteString("    DS Data:\n")
		for _, ds := range a.RDAP.SecureDNS.DSData {
			b.WriteString(fmt.Sprintf("      Algorithm: %d | Digest Type: %d | Key Tag: %d\n", ds.Algorithm, ds.DigestType, ds.KeyTag))
			b.WriteString(fmt.Sprintf("      Digest: %s\n", ds.Digest))
		}
	}
	b.WriteString("    Notices:\n")
	for _, notice := range a.RDAP.Notices {
		b.WriteString(fmt.Sprintf("      [%s]\n", notice.Title))
		for _, desc := range notice.Description {
			b.WriteString(fmt.Sprintf("        %s\n", desc))
		}
	}
	b.WriteString("    Entities:\n")
	for _, entity := range a.RDAP.Entities {
		b.WriteString(fmt.Sprintf("      Role: %s\n", strings.Join(entity.Roles, ", ")))
		for _, vcard := range entity.VCardArray {
			switch vcard.Name {
			case "fn":
				b.WriteString(fmt.Sprintf("      Name: %s\n", strings.Join(vcard.Values, ", ")))
			case "email":
				b.WriteString(fmt.Sprintf("      Email: %s\n", strings.Join(vcard.Values, ", ")))
			case "tel":
				b.WriteString(fmt.Sprintf("      Phone: %s\n", strings.Join(vcard.Values, ", ")))
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("\n" + domainSectionStyle.Render("── WHOIS") + "\n")
	b.WriteString(render.Markdown(fmt.Sprintf("```\n%s\n```", a.Whois)))

	b.WriteString(domainSectionStyle.Render("── Engine Results") + "\n\n")
	var enginesBuf bytes.Buffer
	enginesTable := tablewriter.NewTable(&enginesBuf)
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
	b.WriteString(enginesBuf.String())
	b.WriteString("\n")

	return b.String()
}

func DomainResponse(domain string, d types.DomainResponse) {
	content := DomainContent(domain, d)
	if err := tui.Render(content); err != nil {
		fmt.Print(content)
	}
}
