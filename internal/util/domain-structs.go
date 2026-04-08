package util

type DNSRecord struct {
	Type    string `json:"type"`
	TTL     int    `json:"ttl"`
	Value   string `json:"value"`
	Priority int   `json:"priority,omitempty"`
	RName   string `json:"rname,omitempty"`
	Serial  int    `json:"serial,omitempty"`
	Refresh int    `json:"refresh,omitempty"`
	Retry   int    `json:"retry,omitempty"`
	Expire  int    `json:"expire,omitempty"`
	Minimum int    `json:"minimum,omitempty"`
}

type CertValidity struct {
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

type HTTPSCertificate struct {
	SerialNumber string       `json:"serial_number"`
	Thumbprint   string       `json:"thumbprint"`
	ThumbprintSHA256 string   `json:"thumbprint_sha256"`
	Version      string       `json:"version"`
	Size         int          `json:"size"`
	Validity     CertValidity `json:"validity"`
	Issuer       struct {
		C  string `json:"C"`
		O  string `json:"O"`
		CN string `json:"CN"`
	} `json:"issuer"`
	Subject struct {
		CN string `json:"CN"`
	} `json:"subject"`
}

type RDAPLink struct {
	Href     string `json:"href"`
	Rel      string `json:"rel"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Title    string `json:"title"`
	Media    string `json:"media"`
}

type RDAPEvent struct {
	EventAction string `json:"event_action"`
	EventDate   string `json:"event_date"`
	EventActor  string `json:"event_actor"`
}

type RDAPNotice struct {
	Title       string     `json:"title"`
	Description []string   `json:"description"`
	Type        string     `json:"type"`
	Links       []RDAPLink `json:"links"`
}

type RDAPVCard struct {
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Values     []string          `json:"values"`
	Parameters map[string][]string `json:"parameters"`
}

type RDAPEntity struct {
	ObjectClassName string       `json:"object_class_name"`
	Handle          string       `json:"handle"`
	VCardArray      []RDAPVCard  `json:"vcard_array"`
	Roles           []string     `json:"roles"`
	Port43          string       `json:"port43"`
	Lang            string       `json:"lang"`
	Remarks         []RDAPNotice `json:"remarks"`
	Links           []RDAPLink   `json:"links"`
	Events          []RDAPEvent  `json:"events"`
	Status          []string     `json:"status"`
	Entities        []RDAPEntity `json:"entities"`
}

type RDAPNameserver struct {
	LdhName         string   `json:"ldh_name"`
	ObjectClassName string   `json:"object_class_name"`
	Status          []string `json:"status"`
	Port43          string   `json:"port43"`
}

type RDAPDSData struct {
	Algorithm  int    `json:"algorithm"`
	DigestType int    `json:"digest_type"`
	Digest     string `json:"digest"`
	KeyTag     int    `json:"key_tag"`
}

type RDAPSecureDNS struct {
	DelegationSigned bool         `json:"delegation_signed"`
	ZoneSigned       bool         `json:"zone_signed"`
	DSData           []RDAPDSData `json:"ds_data"`
	MaxSigLife       int          `json:"max_sig_life"`
}

type RDAP struct {
	Handle          string           `json:"handle"`
	LdhName         string           `json:"ldh_name"`
	ObjectClassName string           `json:"object_class_name"`
	Status          []string         `json:"status"`
	Lang            string           `json:"lang"`
	Port43          string           `json:"port43"`
	Events          []RDAPEvent      `json:"events"`
	Links           []RDAPLink       `json:"links"`
	Notices         []RDAPNotice     `json:"notices"`
	Nameservers     []RDAPNameserver `json:"nameservers"`
	Entities        []RDAPEntity     `json:"entities"`
	SecureDNS       RDAPSecureDNS    `json:"secure_dns"`
	RDAPConformance []string         `json:"rdap_conformance"`
}

type DomainAttributes struct {
	Reputation           int                       `json:"reputation"`
	TLD                  string                    `json:"tld"`
	JARM                 string                    `json:"jarm"`
	Whois                string                    `json:"whois"`
	WhoisDate            int64                     `json:"whois_date"`
	CreationDate         int64                     `json:"creation_date"`
	LastUpdateDate       int64                     `json:"last_update_date"`
	LastDNSRecordsDate   int64                     `json:"last_dns_records_date"`
	LastAnalysisDate     int64                     `json:"last_analysis_date"`
	LastModificationDate int64                     `json:"last_modification_date"`
	LastHTTPSCertDate    int64                     `json:"last_https_certificate_date"`
	Tags                 []string                  `json:"tags"`
	LastDNSRecords       []DNSRecord               `json:"last_dns_records"`
	LastAnalysisStats    AnalysisStats             `json:"last_analysis_stats"`
	LastAnalysisResults  map[string]AnalysisResult `json:"last_analysis_results"`
	TotalVotes           TotalVotes                `json:"total_votes"`
	LastHTTPSCertificate HTTPSCertificate          `json:"last_https_certificate"`
	RDAP                 RDAP                      `json:"rdap"`
}

type DomainResponse struct {
	Data struct {
		Attributes DomainAttributes `json:"attributes"`
	} `json:"data"`
}