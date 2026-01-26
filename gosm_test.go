package go_rfc5849_hmac

import (
	"net/http"
	"strings"
	"testing"
)

func TestParamArray_EncodeBytes(t *testing.T) {
	params := ParamArray{
		{"a", "1"},
		{"c", "3"},
		{"b", "2"},
		{"space", "a b"},
		{"special", "a=b"},
	}
	expected := "a=1&b=2&c=3&space=a%20b&special=a%3Db"
	encoded := string(params.EncodeBytes())
	if encoded != expected {
		t.Errorf("EncodeBytes() = %v, want %v", encoded, expected)
	}
}

func TestParamArray_AuthBytes(t *testing.T) {
	params := ParamArray{
		{"a", "1"},
		{"c", "3"},
		{"b", "2"},
	}
	expected := "a=\"1\",b=\"2\",c=\"3\""
	auth := string(params.AuthBytes())
	if auth != expected {
		t.Errorf("AuthBytes() = %v, want %v", auth, expected)
	}
}

func TestSignSha1Hmac1(t *testing.T) {
	// Save original generators and restore them after test
	origTimestampGen := TimestampGenerator
	origNonceGen := NonceGenerator
	defer func() {
		TimestampGenerator = origTimestampGen
		NonceGenerator = origNonceGen
	}()

	// Mock generators
	TimestampGenerator = func() string { return "1234567890" }
	NonceGenerator = func() string { return "nonce_value" }

	// Set keys
	PublicKey = "consumer_key"
	SecretKey = "consumer_secret"
	Token = "token_value"

	u := "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b"
	bodyText := "c2&a3=2+q"
	req, err := http.NewRequest("POST", u, strings.NewReader(bodyText))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	err = SignSha1Hmac1(req, bodyText)
	if err != nil {
		t.Fatalf("SignSha1Hmac1 failed: %v", err)
	}

	auth := req.Header.Get("Authorization")
	// Expected signature based on previous manual check (updated for OAuth space fix)
	// Base String: POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3Dconsumer_key%26oauth_nonce%3Dnonce_value%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1234567890%26oauth_version%3D1.0
	// Key: consumer_secret&token_value
	// Signature: ws+3QTlNmh+txA7FTGVCdt9XwKk=
	// Encoded Signature: ws%2B3QTlNmh%2BtxA7FTGVCdt9XwKk%3D

	expectedStart := "OAuth oauth_consumer_key=\"consumer_key\",oauth_nonce=\"nonce_value\",oauth_signature=\"ws%2B3QTlNmh%2BtxA7FTGVCdt9XwKk%3D\""

	if !strings.HasPrefix(auth, expectedStart) {
		t.Errorf("Authorization header does not start with expected value.\nGot:  %s\nWant prefix: %s", auth, expectedStart)
	}

	expectedParts := []string{
		"oauth_consumer_key=\"consumer_key\"",
		"oauth_nonce=\"nonce_value\"",
		"oauth_signature_method=\"HMAC-SHA1\"",
		"oauth_timestamp=\"1234567890\"",
		"oauth_version=\"1.0\"",
		"oauth_signature=\"ws%2B3QTlNmh%2BtxA7FTGVCdt9XwKk%3D\"",
	}

	for _, part := range expectedParts {
		if !strings.Contains(auth, part) {
			t.Errorf("Authorization header missing part: %s", part)
		}
	}
}
