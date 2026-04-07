package util

type FileAnalysisResult struct {
	Method        string `json:"method"`
	EngineName    string `json:"engine_name"`
	EngineVersion string `json:"engine_version"`
	EngineUpdate  string `json:"engine_update"`
	Category      string `json:"category"`
	Result        string `json:"result"`
}

type FileAnalysisStats struct {
	Malicious        int `json:"malicious"`
	Suspicious       int `json:"suspicious"`
	Undetected       int `json:"undetected"`
	Harmless         int `json:"harmless"`
	Timeout          int `json:"timeout"`
	ConfirmedTimeout int `json:"confirmed-timeout"`
	Failure          int `json:"failure"`
	TypeUnsupported  int `json:"type-unsupported"`
}

type SandboxVerdict struct {
	Category              string   `json:"category"`
	MalwareClassification []string `json:"malware_classification"`
	SandboxName           string   `json:"sandbox_name"`
	Confidence            int      `json:"confidence"`
}

type TRIDEntry struct {
	FileType    string  `json:"file_type"`
	Probability float64 `json:"probability"`
}

type AIResult struct {
	Analysis string `json:"analysis"`
	Verdict  string `json:"verdict"`
	Source   string `json:"source"`
	Category string `json:"category"`
}

type ResourceDetail struct {
	Lang    string  `json:"lang"`
	Chi2    float64 `json:"chi2"`
	FileType string `json:"filetype"`
	Entropy float64 `json:"entropy"`
	SHA256  string  `json:"sha256"`
	Type    string  `json:"type"`
}

type Section struct {
	Name           string  `json:"name"`
	Chi2           float64 `json:"chi2"`
	VirtualAddress int     `json:"virtual_address"`
	Flags          string  `json:"flags"`
	RawSize        int     `json:"raw_size"`
	Entropy        float64 `json:"entropy"`
	VirtualSize    int     `json:"virtual_size"`
	MD5            string  `json:"md5"`
}

type ImportList struct {
	LibraryName       string   `json:"library_name"`
	ImportedFunctions []string `json:"imported_functions"`
}

type ResourceLang struct {
	
}

type PEInfo struct {
	Timestamp       int64                      `json:"timestamp"`
	ImpHash         string                     `json:"imphash"`
	MachineType     int                        `json:"machine_type"`
	EntryPoint      int                        `json:"entry_point"`
	ResourceDetails []ResourceDetail           `json:"resource_details"`
	ResourceLangs   map[string]int             `json:"resource_langs"`
	ResourceTypes   map[string]int             `json:"resource_types"`
	Sections        []Section                  `json:"sections"`
	Imports         []ImportList               `json:"import_list"`
}

type FileAttributes struct {
	Magic                string                        `json:"magic"`
	Reputation           int                           `json:"reputation"`
	MD5                  string                        `json:"md5"`
	SHA1                 string                        `json:"sha1"`
	SHA256               string                        `json:"sha256"`
	MeaningfulName       string                        `json:"meaningful_name"`
	Names                []string                      `json:"names"`
	Tags                 []string                      `json:"tags"`
	TypeDescription      string                        `json:"type_description"`
	TypeExtension        string                        `json:"type_extension"`
	TypeTags             []string                      `json:"type_tags"`
	Size                 int                           `json:"size"`
	TimesSubmitted       int                           `json:"times_submitted"`
	FirstSubmissionDate  int64                         `json:"first_submission_date"`
	LastSubmissionDate   int64                         `json:"last_submission_date"`
	LastModificationDate int64                         `json:"last_modification_date"`
	LastAnalysisDate     int64                         `json:"last_analysis_date"`
	LastAnalysisStats    FileAnalysisStats             `json:"last_analysis_stats"`
	LastAnalysisResults  map[string]FileAnalysisResult `json:"last_analysis_results"`
	TotalVotes           TotalVotes                    `json:"total_votes"`
	SandboxVerdicts      map[string]SandboxVerdict     `json:"sandbox_verdicts"`
	TRID                 []TRIDEntry                   `json:"trid"`
	CrowdsourcedAI       []AIResult                    `json:"crowdsourced_ai_results"`
	SSDEEP               string                        `json:"ssdeep"`
	PEInfo               PEInfo                        `json:"pe_info"`
}

type FileResponse struct {
	Data struct {
		Attributes FileAttributes `json:"attributes"`
	} `json:"data"`
}