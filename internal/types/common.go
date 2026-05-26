package types

type TotalVotes struct {
	Harmless  int `json:"harmless"`
	Malicious int `json:"malicious"`
}

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
