package util

type AnalysisResult struct {
	Method     string `json:"method"`
	EngineName string `json:"engine_name"`
	Category   string `json:"category"`
	Result     string `json:"result"`
}

type AnalysisStats struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Undetected int `json:"undetected"`
	Harmless   int `json:"harmless"`
	Timeout    int `json:"timeout"`
}

type TotalVotes struct {
	Harmless  int `json:"harmless"`
	Malicious int `json:"malicious"`
}

type IPAttributes struct {
	WhoisDate            int64                     `json:"whois_date"`
	LastAnalysisStats    AnalysisStats             `json:"last_analysis_stats"`
	LastModificationDate int64                     `json:"last_modification_date"`
	Reputation           int                       `json:"reputation"`
	Tags                 []string                  `json:"tags"`
	TotalVotes           TotalVotes                `json:"total_votes"`
	LastAnalysisDate     int64                     `json:"last_analysis_date"`
	LastAnalysisResults  map[string]AnalysisResult `json:"last_analysis_results"`
	Whois                string                    `json:"whois"`
}

type IPResponse struct {
	Data struct {
		Attributes IPAttributes `json:"attributes"`
	} `json:"data"`
}