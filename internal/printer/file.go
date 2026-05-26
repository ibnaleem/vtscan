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
	"github.com/olekukonko/tablewriter/tw"
)

func FileResponse(f types.FileResponse) {
	lastAnalysisDate     := time.Unix(f.Data.Attributes.LastAnalysisDate, 0).Format("2006-01-02 15:04:05")
	firstSubmissionDate  := time.Unix(f.Data.Attributes.FirstSubmissionDate, 0).Format("2006-01-02 15:04:05")
	lastModificationDate := time.Unix(f.Data.Attributes.LastModificationDate, 0).Format("2006-01-02 15:04:05")
	lastSubmissionDate   := time.Unix(f.Data.Attributes.LastSubmissionDate, 0).Format("2006-01-02 15:04:05")

	fmt.Println(strings.Repeat("=", 85))
	fmt.Println()

	fmt.Printf("File: %s\n", strings.Join(f.Data.Attributes.Names, ", "))
	fmt.Println()

	fmt.Printf("MD5    :  %s\n", f.Data.Attributes.MD5)
	fmt.Printf("SHA1   :  %s\n", f.Data.Attributes.SHA1)
	fmt.Printf("SHA256 :  %s\n", f.Data.Attributes.SHA256)
	fmt.Println()

	fmt.Printf("Last Modified: %s\n", lastModificationDate)
	fmt.Println()

	fmt.Printf("Type: %s (%s)\n", f.Data.Attributes.TypeDescription, f.Data.Attributes.TypeExtension)
	fmt.Printf("Size: %d bytes\n", f.Data.Attributes.Size)
	fmt.Printf("Magic: %s\n", f.Data.Attributes.Magic)
	fmt.Printf("Reputation: %d\n", f.Data.Attributes.Reputation)

	if len(f.Data.Attributes.Tags) == 0 {
		fmt.Println("Tags: None")
	} else {
		fmt.Printf("Tags: %s\n", strings.Join(f.Data.Attributes.Tags, ", "))
	}

	if len(f.Data.Attributes.TypeTags) == 0 {
		fmt.Println("Type Tags: None")
	} else {
		fmt.Printf("Type Tags: %s\n", strings.Join(f.Data.Attributes.TypeTags, ", "))
	}

	fmt.Println()
	fmt.Println("Submission:")
	fmt.Printf("  First : %s\n", firstSubmissionDate)
	fmt.Printf("  Last  : %s\n", lastSubmissionDate)
	fmt.Printf("  Times : %d\n", f.Data.Attributes.TimesSubmitted)
	fmt.Println()

	fmt.Printf("Last Analysis: %s\n", lastAnalysisDate)
	fmt.Printf("  Malicious:        %s\n", theme.Red(strconv.Itoa(f.Data.Attributes.LastAnalysisStats.Malicious)))
	fmt.Printf("  Suspicious:       %s\n", theme.Red(strconv.Itoa(f.Data.Attributes.LastAnalysisStats.Suspicious)))
	fmt.Printf("  Undetected:       %s\n", theme.Blue(strconv.Itoa(f.Data.Attributes.LastAnalysisStats.Undetected)))
	fmt.Printf("  Harmless:         %s\n", theme.Green(strconv.Itoa(f.Data.Attributes.LastAnalysisStats.Harmless)))
	fmt.Printf("  Timeout:          %s\n", theme.Red(strconv.Itoa(f.Data.Attributes.LastAnalysisStats.Timeout)))
	fmt.Printf("  Type Unsupported: %d\n", f.Data.Attributes.LastAnalysisStats.TypeUnsupported)
	fmt.Println()

	fmt.Println("Community Votes:")
	fmt.Printf("  Harmless  : %s\n", theme.Green(strconv.Itoa(f.Data.Attributes.TotalVotes.Harmless)))
	fmt.Printf("  Malicious : %s\n", theme.Red(strconv.Itoa(f.Data.Attributes.TotalVotes.Malicious)))
	fmt.Println()

	for _, ai := range f.Data.Attributes.CrowdsourcedAI {
		fmt.Println(strings.Repeat("⎯", 85))
		fmt.Printf("AI Analysis (source: %s)\n", ai.Source)
		fmt.Printf("  Verdict: %s\n", ai.Verdict)
		fmt.Printf("  Category: %s\n", ai.Category)
		fmt.Println()
		fmt.Printf("  %s\n", ai.Analysis)
		fmt.Println()
	}

	fmt.Println()

	table := tablewriter.NewWriter(os.Stdout)
	table.Header([]string{"Engine", "Engine Version", "Engine Update", "Method", "Category", "Result"})

	for _, entry := range f.Data.Attributes.LastAnalysisResults {
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
		table.Append([]string{entry.EngineName, entry.EngineVersion, entry.EngineUpdate, entry.Method, cat, res})
	}
	table.Render()

	fmt.Println()
	fmt.Println("Sandbox Verdicts:")

	table = tablewriter.NewWriter(os.Stdout)
	table.Header([]string{"Sandbox", "Category", "Malware Classifications", "Confidence"})

	for _, sandbox := range f.Data.Attributes.SandboxVerdicts {
		var cat string
		switch sandbox.Category {
		case "harmless":
			cat = theme.Green(sandbox.Category)
		case "malicious":
			cat = theme.Red(sandbox.Category)
		default:
			cat = sandbox.Category
		}
		table.Append([]string{sandbox.SandboxName, cat, strings.Join(sandbox.MalwareClassification, ", "), strconv.Itoa(sandbox.Confidence)})
	}
	table.Render()

	fmt.Println()
	fmt.Println("PE Information:")
	fmt.Printf("  Entry Point  : %d\n", f.Data.Attributes.PEInfo.EntryPoint)
	fmt.Printf("  Machine Type : %d\n", f.Data.Attributes.PEInfo.MachineType)
	fmt.Printf("  Imphash      : %s\n", f.Data.Attributes.PEInfo.ImpHash)
	fmt.Printf("  Timestamp    : %d\n", f.Data.Attributes.PEInfo.Timestamp)

	fmt.Println()
	fmt.Println("Resource Langs:")
	for key, value := range f.Data.Attributes.PEInfo.ResourceLangs {
		fmt.Printf("  %s: %d\n", key, value)
	}

	fmt.Println()
	fmt.Println("Resource Types:")
	for key, value := range f.Data.Attributes.PEInfo.ResourceTypes {
		fmt.Printf("  %s: %d\n", key, value)
	}

	fmt.Println()
	fmt.Println("Resource Details:")

	table = tablewriter.NewWriter(os.Stdout)
	table.Header([]string{"Lang", "Type", "File Type", "Chi2", "Entropy", "SHA256"})

	for _, r := range f.Data.Attributes.PEInfo.ResourceDetails {
		table.Append([]string{
			r.Lang,
			r.Type,
			r.FileType,
			strconv.FormatFloat(r.Chi2, 'f', -1, 64),
			strconv.FormatFloat(r.Entropy, 'f', -1, 64),
			r.SHA256,
		})
	}
	table.Render()

	fmt.Println()
	fmt.Println("Sections:")

	table = tablewriter.NewWriter(os.Stdout)
	table.Header([]string{"Section Name", "Flags", "Chi2", "Raw Size", "Virtual Size", "Virtual Address", "Entropy", "MD5"})

	for _, s := range f.Data.Attributes.PEInfo.Sections {
		table.Append([]string{
			s.Name,
			s.Flags,
			strconv.FormatFloat(s.Chi2, 'f', -1, 64),
			strconv.Itoa(s.RawSize),
			strconv.Itoa(s.VirtualSize),
			strconv.Itoa(s.VirtualAddress),
			strconv.FormatFloat(s.Entropy, 'f', -1, 64),
			s.MD5,
		})
	}
	table.Render()

	fmt.Println()
	fmt.Println("Imported Libraries:")

	for _, importList := range f.Data.Attributes.PEInfo.Imports {
		t := tablewriter.NewTable(os.Stdout)
		t.Configure(func(cfg *tablewriter.Config) {
			cfg.Header.Formatting.AutoFormat = tw.Off
		})
		t.Header([]string{importList.LibraryName})
		t.Append([]string{strings.Join(importList.ImportedFunctions, "\n")})
		t.Render()
		fmt.Println()
	}

	fmt.Println()

	if len(f.Data.Attributes.TRID) != 0 {
		fmt.Println("TRID:")

		t := tablewriter.NewTable(os.Stdout)
		t.Header([]string{"File Type", "Probability"})

		for _, trid := range f.Data.Attributes.TRID {
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
		t.Render()
	}

	fmt.Println()
}
