A very basic simple RFC5849 SHA1 HMAC implementation.

Usage:

```
package main

import (
	"net/http"
	"strings"
	"log"
	"bytes"
	"github.com/arran4/go-rfc5849-hmac"
)

func main() {
	u := "https://localhost/api/?format=json"
	bodyText := 
	req, err := http.NewRequest("POST", u, strings.NewReader(bodyText))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	go_rfc5849_hmac.PublicKey = 
	go_rfc5849_hmac.SecretKey = 
	go_rfc5849_hmac.SignSha1Hmac1(req, bodyText)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	buff := bytes.NewBuffer(nil)
	res.Write(buff)
	log.Printf("%s", buff.String())

}
```
