package printer

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/ibnaleem/vtscan/internal/theme"
	"github.com/ibnaleem/vtscan/internal/tui"
	"github.com/ibnaleem/vtscan/internal/types"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
)

var (
	fileHeaderStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86")).PaddingLeft(2)
	fileSectionStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99")).PaddingLeft(2)
	fileLabelStyle   = lipgloss.NewStyle().Width(24).Foreground(lipgloss.Color("245")).PaddingLeft(4)
)

func renderTable(header []string, rows func(t *tablewriter.Table)) string {
	var buf bytes.Buffer
	t := tablewriter.NewWriter(&buf)
	t.Header(header)
	rows(t)
	t.Render()
	return buf.String()
}

func FileContent(f types.FileResponse) string {
	a := f.Data.Attributes
	var b strings.Builder

	lastAnalysisDate     := time.Unix(a.LastAnalysisDate, 0).Format("2006-01-02 15:04:05")
	firstSubmissionDate  := time.Unix(a.FirstSubmissionDate, 0).Format("2006-01-02 15:04:05")
	lastModificationDate := time.Unix(a.LastModificationDate, 0).Format("2006-01-02 15:04:05")
	lastSubmissionDate   := time.Unix(a.LastSubmissionDate, 0).Format("2006-01-02 15:04:05")

	b.WriteString("\n")
	if len(a.Names) > 0 {
		b.WriteString(fileHeaderStyle.Render(strings.Join(a.Names, ", ")) + "\n\n")
	}

	b.WriteString(fileLabelStyle.Render("MD5") + a.MD5 + "\n")
	b.WriteString(fileLabelStyle.Render("SHA1") + a.SHA1 + "\n")
	b.WriteString(fileLabelStyle.Render("SHA256") + a.SHA256 + "\n")
	b.WriteString(fileLabelStyle.Render("SSDEEP") + a.SSDEEP + "\n")

	b.WriteString("\n" + fileSectionStyle.Render("── File Info") + "\n\n")
	b.WriteString(fileLabelStyle.Render("Type") + fmt.Sprintf("%s (%s)", a.TypeDescription, a.TypeExtension) + "\n")
	b.WriteString(fileLabelStyle.Render("Size") + fmt.Sprintf("%d bytes", a.Size) + "\n")
	b.WriteString(fileLabelStyle.Render("Magic") + a.Magic + "\n")
	b.WriteString(fileLabelStyle.Render("Reputation") + fmt.Sprintf("%d", a.Reputation) + "\n")
	b.WriteString(fileLabelStyle.Render("Modified") + lastModificationDate + "\n")
	if len(a.Tags) == 0 {
		b.WriteString(fileLabelStyle.Render("Tags") + "None\n")
	} else {
		b.WriteString(fileLabelStyle.Render("Tags") + strings.Join(a.Tags, ", ") + "\n")
	}
	if len(a.TypeTags) == 0 {
		b.WriteString(fileLabelStyle.Render("Type Tags") + "None\n")
	} else {
		b.WriteString(fileLabelStyle.Render("Type Tags") + strings.Join(a.TypeTags, ", ") + "\n")
	}

	b.WriteString("\n" + fileSectionStyle.Render("── Submission") + "\n\n")
	b.WriteString(fileLabelStyle.Render("First") + firstSubmissionDate + "\n")
	b.WriteString(fileLabelStyle.Render("Last") + lastSubmissionDate + "\n")
	b.WriteString(fileLabelStyle.Render("Times") + strconv.Itoa(a.TimesSubmitted) + "\n")

	b.WriteString("\n" + fileSectionStyle.Render("── Last Analysis") + "\n\n")
	b.WriteString(fileLabelStyle.Render("Date") + lastAnalysisDate + "\n")
	b.WriteString(fileLabelStyle.Render("Malicious") + theme.Red(strconv.Itoa(a.LastAnalysisStats.Malicious)) + "\n")
	b.WriteString(fileLabelStyle.Render("Suspicious") + theme.Red(strconv.Itoa(a.LastAnalysisStats.Suspicious)) + "\n")
	b.WriteString(fileLabelStyle.Render("Undetected") + theme.Blue(strconv.Itoa(a.LastAnalysisStats.Undetected)) + "\n")
	b.WriteString(fileLabelStyle.Render("Harmless") + theme.Green(strconv.Itoa(a.LastAnalysisStats.Harmless)) + "\n")
	b.WriteString(fileLabelStyle.Render("Timeout") + theme.Red(strconv.Itoa(a.LastAnalysisStats.Timeout)) + "\n")
	b.WriteString(fileLabelStyle.Render("Type Unsupported") + strconv.Itoa(a.LastAnalysisStats.TypeUnsupported) + "\n")

	b.WriteString("\n" + fileSectionStyle.Render("── Community Votes") + "\n\n")
	b.WriteString(fileLabelStyle.Render("Harmless") + theme.Green(strconv.Itoa(a.TotalVotes.Harmless)) + "\n")
	b.WriteString(fileLabelStyle.Render("Malicious") + theme.Red(strconv.Itoa(a.TotalVotes.Malicious)) + "\n")

	if len(a.CrowdsourcedAI) > 0 {
		b.WriteString("\n" + fileSectionStyle.Render("── AI Analysis") + "\n\n")
		for _, ai := range a.CrowdsourcedAI {
			b.WriteString(fileLabelStyle.Render("Source") + ai.Source + "\n")
			b.WriteString(fileLabelStyle.Render("Verdict") + ai.Verdict + "\n")
			b.WriteString(fileLabelStyle.Render("Category") + ai.Category + "\n")
			b.WriteString("\n    " + ai.Analysis + "\n\n")
		}
	}

	b.WriteString("\n" + fileSectionStyle.Render("── Engine Results") + "\n\n")
	b.WriteString(renderTable([]string{"Engine", "Engine Version", "Engine Update", "Method", "Category", "Result"}, func(t *tablewriter.Table) {
		for _, entry := range a.LastAnalysisResults {
			var cat, res string
			switch entry.Category {
			case "clean":
				cat = theme.Green(entry.Category)
				res = theme.Green(entry.Result)
			case "malicious":
				cat = theme.Red(entry.Category)
				res = theme.Red(entry.Result)
			default:
				cat = entry.Category
				res = entry.Result
			}
			t.Append([]string{entry.EngineName, entry.EngineVersion, entry.EngineUpdate, entry.Method, cat, res})
		}
	}))

	b.WriteString("\n" + fileSectionStyle.Render("── Sandbox Verdicts") + "\n\n")
	b.WriteString(renderTable([]string{"Sandbox", "Category", "Malware Classifications", "Confidence"}, func(t *tablewriter.Table) {
		for _, sandbox := range a.SandboxVerdicts {
			var cat string
			switch sandbox.Category {
			case "harmless":
				cat = theme.Green(sandbox.Category)
			case "malicious":
				cat = theme.Red(sandbox.Category)
			default:
				cat = sandbox.Category
			}
			t.Append([]string{sandbox.SandboxName, cat, strings.Join(sandbox.MalwareClassification, ", "), strconv.Itoa(sandbox.Confidence)})
		}
	}))

	b.WriteString("\n" + fileSectionStyle.Render("── PE Information") + "\n\n")
	b.WriteString(fileLabelStyle.Render("Entry Point") + strconv.Itoa(a.PEInfo.EntryPoint) + "\n")
	b.WriteString(fileLabelStyle.Render("Machine Type") + strconv.Itoa(a.PEInfo.MachineType) + "\n")
	b.WriteString(fileLabelStyle.Render("Imphash") + a.PEInfo.ImpHash + "\n")
	b.WriteString(fileLabelStyle.Render("Timestamp") + fmt.Sprintf("%d", a.PEInfo.Timestamp) + "\n")

	if len(a.PEInfo.ResourceLangs) > 0 {
		b.WriteString("\n    Resource Langs:\n")
		for key, value := range a.PEInfo.ResourceLangs {
			b.WriteString(fmt.Sprintf("      %s: %d\n", key, value))
		}
	}

	if len(a.PEInfo.ResourceTypes) > 0 {
		b.WriteString("\n    Resource Types:\n")
		for key, value := range a.PEInfo.ResourceTypes {
			b.WriteString(fmt.Sprintf("      %s: %d\n", key, value))
		}
	}

	if len(a.PEInfo.ResourceDetails) > 0 {
		b.WriteString("\n" + fileSectionStyle.Render("── Resource Details") + "\n\n")
		b.WriteString(renderTable([]string{"Lang", "Type", "File Type", "Chi2", "Entropy", "SHA256"}, func(t *tablewriter.Table) {
			for _, r := range a.PEInfo.ResourceDetails {
				t.Append([]string{
					r.Lang, r.Type, r.FileType,
					strconv.FormatFloat(r.Chi2, 'f', -1, 64),
					strconv.FormatFloat(r.Entropy, 'f', -1, 64),
					r.SHA256,
				})
			}
		}))
	}

	if len(a.PEInfo.Sections) > 0 {
		b.WriteString("\n" + fileSectionStyle.Render("── Sections") + "\n\n")
		b.WriteString(renderTable([]string{"Section Name", "Flags", "Chi2", "Raw Size", "Virtual Size", "Virtual Address", "Entropy", "MD5"}, func(t *tablewriter.Table) {
			for _, s := range a.PEInfo.Sections {
				t.Append([]string{
					s.Name, s.Flags,
					strconv.FormatFloat(s.Chi2, 'f', -1, 64),
					strconv.Itoa(s.RawSize),
					strconv.Itoa(s.VirtualSize),
					strconv.Itoa(s.VirtualAddress),
					strconv.FormatFloat(s.Entropy, 'f', -1, 64),
					s.MD5,
				})
			}
		}))
	}

	if len(a.PEInfo.Imports) > 0 {
		b.WriteString("\n" + fileSectionStyle.Render("── Imported Libraries") + "\n\n")
		for _, importList := range a.PEInfo.Imports {
			var libBuf bytes.Buffer
			t := tablewriter.NewTable(&libBuf)
			t.Configure(func(cfg *tablewriter.Config) {
				cfg.Header.Formatting.AutoFormat = tw.Off
			})
			t.Header([]string{importList.LibraryName})
			t.Append([]string{strings.Join(importList.ImportedFunctions, "\n")})
			t.Render()
			b.WriteString(libBuf.String())
			b.WriteString("\n")
		}
	}

	if len(a.TRID) > 0 {
		b.WriteString("\n" + fileSectionStyle.Render("── TRID") + "\n\n")
		b.WriteString(renderTable([]string{"File Type", "Probability"}, func(t *tablewriter.Table) {
			for _, trid := range a.TRID {
				prob := strconv.FormatFloat(trid.Probability, 'f', -1, 64)
				var coloured string
				switch {
				case trid.Probability < 33:
					coloured = theme.Red(prob)
				case trid.Probability < 66:
					coloured = theme.Yellow(prob)
				default:
					coloured = theme.Green(prob)
				}
				t.Append([]string{trid.FileType, coloured})
			}
		}))
	}

	b.WriteString("\n")
	return b.String()
}

func FileResponse(f types.FileResponse) {
	content := FileContent(f)
	if err := tui.Render(content); err != nil {
		fmt.Print(content)
	}
}
