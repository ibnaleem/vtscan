package types

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

type CommentVotes struct {
	Positive int `json:"positive"`
	Negative int `json:"negative"`
	Abuse    int `json:"abuse"`
}

type CommentAttributes struct {
	Date  int64        `json:"date"`
	Text  string       `json:"text"`
	Tags  []string     `json:"tags"`
	Votes CommentVotes `json:"votes"`
}

type CommentAuthor struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type CommentAuthorRelationship struct {
	Data CommentAuthor `json:"data"`
}

type CommentRelationships struct {
	Author CommentAuthorRelationship `json:"author"`
}

type IPComment struct {
	ID            string               `json:"id"`
	Type          string               `json:"type"`
	Attributes    CommentAttributes    `json:"attributes"`
	Relationships CommentRelationships `json:"relationships"`
}

type IPCommentsMeta struct {
	Count  int    `json:"count"`
	Cursor string `json:"cursor"`
}

type IPCommentsResponse struct {
	Data []IPComment    `json:"data"`
	Meta IPCommentsMeta `json:"meta"`
}
