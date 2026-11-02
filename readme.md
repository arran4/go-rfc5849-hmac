# go-rfc5849-hmac

> **Archived for now (November 2026).** This repository is not actively maintained and is provided as-is. If you use this project and would like to see it revived, please [contact me via my GitHub profile](https://github.com/arran4) and mention `go-rfc5849-hmac`. I'm open to unarchiving it if there's a need.

A very basic simple RFC5849 (OAuth 1.0a) SHA1 HMAC implementation in Go.

## Usage

```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	go_rfc5849_hmac "github.com/arran4/go-rfc5849-hmac"
)

func main() {
	u := "https://example.com/api/?format=json"
	bodyText := `{"key": "value"}`

	req, err := http.NewRequest("POST", u, strings.NewReader(bodyText))
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")

	// Set your credentials
	go_rfc5849_hmac.PublicKey = "your_consumer_key"
	go_rfc5849_hmac.SecretKey = "your_consumer_secret"
	go_rfc5849_hmac.Token = "your_token_secret" // Leave empty if not using token

	// Sign the request
	// Note: bodyText is passed to be included in signature if Content-Type is application/x-www-form-urlencoded
	err = go_rfc5849_hmac.SignSha1Hmac1(req, bodyText)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Authorization Header:", req.Header.Get("Authorization"))

	// Execute request
	// client := &http.Client{}
	// resp, err := client.Do(req)
	// ...
}
```
