package util 

import (
	"os"
	"io"
	"fmt"
	"time"
	"regexp"
	"strconv"
	"strings"
	"crypto/sha256"
  "github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
)

type Theme struct {
	Reset     string // Reset formatting
	Bold      string // Bold text
	Underline string // Underlined text
	Red       string // Red text
	Green     string // Green text
	Yellow    string // Yellow text
	Blue      string // Blue text
	Magenta   string // Magenta text
	Cyan      string // Cyan text
	White     string // White text
	Gray      string // Gray text
}

// LightTheme defines colors optimized for light terminal backgrounds.
var LightTheme = Theme{
	Reset:     "\033[0m",
	Bold:      "\033[1m",
	Underline: "\033[4m",
	Red:       "\033[31m", // Bright red for light background
	Green:     "\033[32m", // Forest green
	Yellow:    "\033[33m", // Dark yellow
	Blue:      "\033[34m", // Navy blue
	Magenta:   "\033[35m", // Dark magenta
	Cyan:      "\033[36m", // Dark cyan
	White:     "\033[37m", // Black for light background
	Gray:      "\033[90m", // Dark gray
}

// DarkTheme defines colors optimized for dark terminal backgrounds.
var DarkTheme = Theme{
	Reset:     "\033[0m",
	Bold:      "\033[1m",
	Underline: "\033[4m",
	Red:       "\033[91m", // Light red for dark background
	Green:     "\033[92m", // Light green
	Yellow:    "\033[93m", // Bright yellow
	Blue:      "\033[94m", // Light blue
	Magenta:   "\033[95m", // Light magenta
	Cyan:      "\033[96m", // Light cyan
	White:     "\033[97m", // White for dark background
	Gray:      "\033[37m", // Light gray
}

func CheckError(err error) {
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}

func CheckHash(input string) bool {
	md5    := regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	sha1   := regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	sha256 := regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

	return md5.MatchString(input) || sha1.MatchString(input) || sha256.MatchString(input)
}

func CalculateFileSHA256Hash(path string) (string, error) {

	f, err := os.OpenFile(path, os.O_RDONLY, 0644)

	if err != nil {
		return "", err
	}

	defer f.Close()

	sha256Hasher := sha256.New()

	_, err = io.Copy(sha256Hasher, f)

	if err != nil {
		return "", err
	}

	hash := sha256Hasher.Sum(nil)

	return fmt.Sprintf("%x", hash), nil

}

func PrintFileResponse(fileResponse FileResponse) {
	lastAnalysisDate := time.Unix(fileResponse.Data.Attributes.LastAnalysisDate, 0).Format("2006-01-02 15:04:05")
	firstSubmissionDate := time.Unix(fileResponse.Data.Attributes.FirstSubmissionDate, 0).Format("2006-01-02 15:04:05")
	lastModificationDate := time.Unix(fileResponse.Data.Attributes.LastModificationDate, 0).Format("2006-01-02 15:04:05")
	lastSubmissionDate := time.Unix(fileResponse.Data.Attributes.LastSubmissionDate, 0).Format("2006-01-02 15:04:05")	
	
	
	fmt.Println(strings.Repeat("=", 85))
	fmt.Println()

	fmt.Printf("File: %s\n", strings.Join(fileResponse.Data.Attributes.Names, ", "))

	fmt.Println()

	fmt.Printf("MD5    :  %s\n", fileResponse.Data.Attributes.MD5)
	fmt.Printf("SHA1   :  %s\n", fileResponse.Data.Attributes.SHA1)
	fmt.Printf("SHA256 :  %s\n", fileResponse.Data.Attributes.SHA256)

	fmt.Println()

	fmt.Printf("Last Modified: %s\n", lastModificationDate)

	fmt.Println()

	fmt.Printf("Type: %s (%s)\n", fileResponse.Data.Attributes.TypeDescription, fileResponse.Data.Attributes.TypeExtension)
	fmt.Printf("Size: %d bytes\n", fileResponse.Data.Attributes.Size)
	fmt.Printf("Magic: %s\n", fileResponse.Data.Attributes.Magic)
	fmt.Printf("Reputation: %d\n", fileResponse.Data.Attributes.Reputation)

	if len(fileResponse.Data.Attributes.Tags) == 0 {
		fmt.Println("Tags: None")
	} else {
		fmt.Printf("Tags: %s\n", strings.Join(fileResponse.Data.Attributes.Tags, ", "))
	}

	if len(fileResponse.Data.Attributes.TypeTags) == 0 {
		fmt.Println("Type Tags: None")
	} else {
		fmt.Printf("Type Tags: %s\n", strings.Join(fileResponse.Data.Attributes.TypeTags, ", "))
	}
	
	fmt.Println()

	fmt.Println("Submission:")
	fmt.Printf("  First : %s\n", firstSubmissionDate)
	fmt.Printf("  Last  : %s\n", lastSubmissionDate)
	fmt.Printf("  Times : %d\n", fileResponse.Data.Attributes.TimesSubmitted)

	fmt.Println()

	fmt.Printf("Last Analysis: %s\n", lastAnalysisDate)
	fmt.Printf("  Malicious:        " + DarkTheme.Red + "%s\n" + DarkTheme.Reset, strconv.Itoa(fileResponse.Data.Attributes.LastAnalysisStats.Malicious))
	fmt.Printf("  Suspicious:       " + DarkTheme.Red + "%s\n" + DarkTheme.Reset, strconv.Itoa(fileResponse.Data.Attributes.LastAnalysisStats.Suspicious))
	fmt.Printf("  Undetected:       " + DarkTheme.Blue + "%s\n" + DarkTheme.Reset, strconv.Itoa(fileResponse.Data.Attributes.LastAnalysisStats.Undetected))
	fmt.Printf("  Harmless:         " + DarkTheme.Green + "%s\n" + DarkTheme.Reset, strconv.Itoa(fileResponse.Data.Attributes.LastAnalysisStats.Harmless))
	fmt.Printf("  Timeout:          " + DarkTheme.Red + "%s\n" + DarkTheme.Reset, strconv.Itoa(fileResponse.Data.Attributes.LastAnalysisStats.Timeout))
	fmt.Printf("  Type Unsupported: %d\n", fileResponse.Data.Attributes.LastAnalysisStats.TypeUnsupported)

	fmt.Println()

	fmt.Println("Community Votes:")
	fmt.Printf("  Harmless  : " + DarkTheme.Green + "%d\n" + DarkTheme.Reset, fileResponse.Data.Attributes.TotalVotes.Harmless)
	fmt.Printf("  Malicious : " + DarkTheme.Red + "%d\n" + DarkTheme.Reset, fileResponse.Data.Attributes.TotalVotes.Malicious)

	fmt.Println()

	for _, ai := range fileResponse.Data.Attributes.CrowdsourcedAI {

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

	var colourCodedCategory string
	var colourCodedResult string

	for _, entry := range fileResponse.Data.Attributes.LastAnalysisResults {
		if entry.Category == "clean" {
					colourCodedCategory =  DarkTheme.Green + entry.Category +  DarkTheme.Reset
					colourCodedResult   =  DarkTheme.Green + entry.Result +  DarkTheme.Reset
				} else if entry.Category == "malicious" {
					colourCodedCategory =  DarkTheme.Red + entry.Category +  DarkTheme.Reset
					colourCodedResult   =  DarkTheme.Red + entry.Result +  DarkTheme.Reset
				} else {
					colourCodedCategory = entry.Category
					colourCodedResult = entry.Result
				}

				table.Append([]string{entry.EngineName, entry.EngineVersion, entry.EngineUpdate, entry.Method, colourCodedCategory, colourCodedResult})
	}

	table.Render()

	fmt.Println()
	fmt.Println()

	fmt.Println("Sandbox Verdicts:")

	table = tablewriter.NewWriter(os.Stdout)


	table.Header([]string{"Sandbox", "Category", "Malware Classifications", "Confidence"})

	for _, sandbox := range fileResponse.Data.Attributes.SandboxVerdicts {
		if sandbox.Category == "harmless" {
					colourCodedCategory =  DarkTheme.Green + sandbox.Category +  DarkTheme.Reset
				} else if sandbox.Category == "malicious" {
					colourCodedCategory =  DarkTheme.Red + sandbox.Category +  DarkTheme.Reset
				} else {
					colourCodedCategory = sandbox.Category
				}
		
		stringConfidence := strconv.Itoa(sandbox.Confidence)
		table.Append([]string{sandbox.SandboxName, colourCodedCategory, strings.Join(sandbox.MalwareClassification, ", "), stringConfidence})
	}

	fmt.Println()


	fmt.Println("PE Information:")
	fmt.Printf("  Entry Point  : %d\n", fileResponse.Data.Attributes.PEInfo.EntryPoint)
	fmt.Printf("  Machine Type : %d\n", fileResponse.Data.Attributes.PEInfo.MachineType)
	fmt.Printf("  Imphash      : %s\n", fileResponse.Data.Attributes.PEInfo.ImpHash)
	fmt.Printf("  Timestamp    : %d\n", fileResponse.Data.Attributes.PEInfo.Timestamp)
	
	fmt.Println()
	fmt.Println("Resource Langs:")

	for key, value := range fileResponse.Data.Attributes.PEInfo.ResourceLangs {

		fmt.Printf("  %s: %d\n", key, value)

	}

	fmt.Println()
	fmt.Println("Resource Types:")

	for key, value := range fileResponse.Data.Attributes.PEInfo.ResourceTypes {
		fmt.Printf("  %s: %d\n", key, value)
	}


	fmt.Println()
	fmt.Println("Resource Details:")

	table = tablewriter.NewWriter(os.Stdout)
	table.Header([]string{"Lang", "Type", "File Type", "Chi2", "Entropy", "SHA256"})

	for _, resource := range fileResponse.Data.Attributes.PEInfo.ResourceDetails {
		stringChi2 := strconv.FormatFloat(resource.Chi2, 'f', -1, 64)
		stringEntropy := strconv.FormatFloat(resource.Entropy, 'f', -1, 64)

		table.Append([]string{resource.Lang, resource.Type, resource.FileType, stringChi2, stringEntropy, resource.SHA256})
	}

	table.Render()

	fmt.Println()


	fmt.Println("Sections:")

	table = tablewriter.NewWriter(os.Stdout)
	table.Header([]string{"Section Name", "Flags", "Chi2", "Raw Size", "Virtual Size", "Virtual Address", "Entropy", "MD5"})

	for _, section := range fileResponse.Data.Attributes.PEInfo.Sections {

		stringChi2           := strconv.FormatFloat(section.Chi2, 'f', -1, 64)
		stringEntropy        := strconv.FormatFloat(section.Entropy, 'f', -1, 64)
		stringRawSize        := strconv.Itoa(section.RawSize)
		stringVirtualSize    := strconv.Itoa(section.VirtualSize)
		stringVirtualAddress := strconv.Itoa(section.VirtualAddress)

		table.Append([]string{section.Name, section.Flags, stringChi2, stringRawSize, stringVirtualSize, stringVirtualAddress, stringEntropy, section.MD5})
	}

	table.Render()

	fmt.Println()

	fmt.Println("Imported Libraries:")


	for _, importList := range fileResponse.Data.Attributes.PEInfo.Imports {
		table = tablewriter.NewTable(os.Stdout)

		table.Configure(func(cfg *tablewriter.Config) {
    cfg.Header.Formatting.AutoFormat = tw.Off
	})

		table.Header([]string{importList.LibraryName})
		table.Append([]string{strings.Join(importList.ImportedFunctions, "\n")})
		table.Render()
		fmt.Println()
	}


	fmt.Println()

	fmt.Println("TRID:")

	table = tablewriter.NewTable(os.Stdout)

	table.Header([]string{"File Type", "Probability"})

	var colouredProbability string

	for _, trid := range fileResponse.Data.Attributes.TRID {

		stringProbability := strconv.FormatFloat(trid.Probability, 'f', -1, 64)

		if trid.Probability < 33 {
			colouredProbability = DarkTheme.Red + stringProbability + DarkTheme.Reset
		} else if trid.Probability > 33 && trid.Probability < 66 {
			colouredProbability = DarkTheme.Yellow + stringProbability + DarkTheme.Reset
		} else {
			colouredProbability = DarkTheme.Green + stringProbability + DarkTheme.Reset
		}

		table.Append([]string{trid.FileType, colouredProbability})
		
	}

	fmt.Println()

}