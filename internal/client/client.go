package client

type Client struct {
	APIKey  string
	BaseURL string
}

func NewClient(apikey string) *Client {
	return &Client{
		APIKey: apikey,
		BaseURL: "https://www.virustotal.com/api/v3",
	}
}