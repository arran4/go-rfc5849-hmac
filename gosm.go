package go_rfc5849_hmac

import (
	"net/http"
	"net/url"
	"encoding/base64"
	"strings"
	"crypto/hmac"
	"crypto/sha1"
	"time"
	"strconv"
	"encoding/hex"
	"crypto/rand"
	"sort"
	"mime"
	"bytes"
)

var (
	PublicKey = ""
	SecretKey = ""
	Token = ""
	TimestampGenerator StringResult = DefaultTimestampGenerator
	NonceGenerator StringResult = DefaultNonceGenerator
)

type StringResult func () string

type Pair []string
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

func (array ParamArray) EncodeBytes() []byte {
	if array == nil {
		return []byte("")
	}
	var buf bytes.Buffer
	sort.Sort(array)
	for _, k := range array {
		prefix := url.QueryEscape(k[0]) + "="
		if buf.Len() > 0 {
			buf.WriteByte('&')
		}
		buf.WriteString(prefix)
		buf.WriteString(url.QueryEscape(k[1]))
	}
	return buf.Bytes()
}

func (array ParamArray) AuthBytes() []byte {
	if array == nil {
		return []byte("")
	}
	var buf bytes.Buffer
	keys := make([]string, 0, len(array))
	for _, k := range array {
		keys = append(keys, k[0])
	}
	sort.Sort(array)
	for _, k := range array {
		prefix := url.QueryEscape(k[0]) + "="
		if buf.Len() > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(prefix)
		buf.WriteString("\"" + url.QueryEscape(k[1]) + "\"")
	}
	return buf.Bytes()
}

func DefaultNonceGenerator() string {
	nb := make([]byte, 16)
	if _, err := rand.Read(nb); err != nil {
		return ""
	}
	return hex.EncodeToString(nb)
}

func DefaultTimestampGenerator() string {
	return strconv.Itoa(int(time.Now().Unix()))
}

func SignSha1Hmac1(req *http.Request, body string) error {
	ts := TimestampGenerator()
	nonce := NonceGenerator()
	h := hmac.New(sha1.New, []byte(strings.Join([]string{ url.QueryEscape(SecretKey), url.QueryEscape(Token) }, "&")))

	authorizationParams := []Pair{
		Pair{"oauth_consumer_key", PublicKey},
		Pair{"oauth_nonce",nonce,},
		Pair{"oauth_signature_method","HMAC-SHA1",},
		Pair{"oauth_timestamp",ts,},
		Pair{"oauth_version","1.0",},
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
				params = append(params, Pair{k, v,})
			}
		}
	}

	if req.URL.Query() != nil {
		for k, vs := range req.URL.Query() {
			for _, v := range vs {
				params = append(params, Pair{k, v,})
			}
		}
	}

	u2 := *req.URL
	u2.RawQuery = ""

	oauthparam := ParamArray(params).EncodeBytes()
	signThis := strings.Join([]string{req.Method, url.QueryEscape(u2.String()), url.QueryEscape(string(oauthparam)), },"&")
	h.Write([]byte(signThis))
	hb := h.Sum(nil)
	signature := base64.StdEncoding.EncodeToString(hb)
	authorizationParams = append(authorizationParams, Pair{"oauth_signature", signature,})
	authstring := bytes.NewBufferString("OAuth,")

	authstring.Write(ParamArray(authorizationParams).AuthBytes())
	req.Header.Add("Authorization", authstring.String())

	return nil
}
