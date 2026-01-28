package go_rfc5849_hmac

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	// PublicKey is the OAuth Consumer Key.
	PublicKey = ""
	// SecretKey is the OAuth Consumer Secret.
	SecretKey = ""
	// Token is the OAuth Token Secret.
	Token = ""
	// TimestampGenerator generates the timestamp for the request.
	TimestampGenerator StringResult = DefaultTimestampGenerator
	// NonceGenerator generates the nonce for the request.
	NonceGenerator StringResult = DefaultNonceGenerator
)

// StringResult is a function that returns a string.
type StringResult func() string

// Pair represents a key-value pair.
type Pair []string

// ParamArray is a collection of Pairs, sortable by key.
type ParamArray []Pair

func (p ParamArray) Len() int {
	return len(p)
}

func (p ParamArray) Less(i, j int) bool {
	return p[i][0] < p[j][0]
}

func (p ParamArray) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

// EncodeBytes encodes the parameters into a query string format according to RFC 5849.
func (array ParamArray) EncodeBytes() []byte {
	if array == nil {
		return []byte("")
	}
	var buf bytes.Buffer
	sort.Sort(array)
	for _, k := range array {
		prefix := Escape(k[0]) + "="
		if buf.Len() > 0 {
			buf.WriteByte('&')
		}
		buf.WriteString(prefix)
		buf.WriteString(Escape(k[1]))
	}
	return buf.Bytes()
}

// AuthBytes encodes the parameters into the Authorization header format.
func (array ParamArray) AuthBytes() []byte {
	if array == nil {
		return []byte("")
	}
	var buf bytes.Buffer
	sort.Sort(array)
	for _, k := range array {
		prefix := Escape(k[0]) + "="
		if buf.Len() > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(prefix)
		buf.WriteString("\"" + Escape(k[1]) + "\"")
	}
	return buf.Bytes()
}

// DefaultNonceGenerator returns a random 16-byte hex string.
func DefaultNonceGenerator() string {
	nb := make([]byte, 16)
	if _, err := rand.Read(nb); err != nil {
		return ""
	}
	return hex.EncodeToString(nb)
}

// DefaultTimestampGenerator returns the current unix timestamp as a string.
func DefaultTimestampGenerator() string {
	return strconv.Itoa(int(time.Now().Unix()))
}

// SignSha1Hmac1 signs the request using HMAC-SHA1.
// It adds the Authorization header to the request.
func SignSha1Hmac1(req *http.Request, body string) error {
	ts := TimestampGenerator()
	nonce := NonceGenerator()
	h := hmac.New(sha1.New, []byte(strings.Join([]string{Escape(SecretKey), Escape(Token)}, "&")))

	authorizationParams := []Pair{
		Pair{"oauth_consumer_key", PublicKey},
		Pair{"oauth_nonce", nonce},
		Pair{"oauth_signature_method", "HMAC-SHA1"},
		Pair{"oauth_timestamp", ts},
		Pair{"oauth_version", "1.0"},
	}

	var params ParamArray = append([]Pair{}, authorizationParams...)

	if mt, _, err := mime.ParseMediaType(req.Header.Get("Content-Type")); err != nil {
		return err
	} else if mt != "application/x-www-form-urlencoded" {
		// Ignored but should return error -- Use for this is where it isn't considered.
	} else if ps, err := url.ParseQuery(body); err != nil {
		return err
	} else {
		for k, vs := range ps {
			for _, v := range vs {
				params = append(params, Pair{k, v})
			}
		}
	}

	if req.URL.Query() != nil {
		for k, vs := range req.URL.Query() {
			for _, v := range vs {
				params = append(params, Pair{k, v})
			}
		}
	}

	u2 := *req.URL
	u2.RawQuery = ""

	oauthparam := ParamArray(params).EncodeBytes()
	signThis := strings.Join([]string{req.Method, Escape(u2.String()), Escape(string(oauthparam))}, "&")
	h.Write([]byte(signThis))
	hb := h.Sum(nil)
	signature := base64.StdEncoding.EncodeToString(hb)
	authorizationParams = append(authorizationParams, Pair{"oauth_signature", signature})
	authstring := bytes.NewBufferString("OAuth ")

	authstring.Write(ParamArray(authorizationParams).AuthBytes())
	req.Header.Add("Authorization", authstring.String())

	return nil
}

// Escape encodes a string according to RFC 3986.
// It escapes all characters except unreserved characters (ALPHA, DIGIT, "-", ".", "_", "~").
func Escape(s string) string {
	t := make([]byte, 0, 3*len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			t = append(t, c)
		} else {
			t = append(t, '%')
			t = append(t, "0123456789ABCDEF"[c>>4])
			t = append(t, "0123456789ABCDEF"[c&15])
		}
	}
	return string(t)
}

func isUnreserved(c byte) bool {
	if 'A' <= c && c <= 'Z' {
		return true
	}
	if 'a' <= c && c <= 'z' {
		return true
	}
	if '0' <= c && c <= '9' {
		return true
	}
	switch c {
	case '-', '.', '_', '~':
		return true
	}
	return false
}
