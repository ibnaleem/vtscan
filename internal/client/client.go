package client

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

var DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.3"

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

func (c *Client) Get(endpoint string) ([]byte, int, error) {

	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	url := fmt.Sprintf("%s/%s", c.BaseURL, endpoint) 

	req, err := http.NewRequest(http.MethodGet, url, nil)
	
	if err != nil {
		return nil, 400, err
	}	

	req.Header.Set("User-Agent", DefaultUserAgent)
	req.Header.Set("accept", "application/json")
	req.Header.Set("x-apikey", c.APIKey)
	res, err := client.Do(req)

	if err != nil {
		return nil, res.StatusCode, err
	}	

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)

	if err != nil {
		return nil, res.StatusCode, err
	}	

	return body, res.StatusCode, nil

}