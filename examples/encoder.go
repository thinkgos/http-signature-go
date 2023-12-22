//go:build encoder

package main

import (
	"bytes"
	"io"
	"net/http"
	"time"

	httpsign "github.com/thinkgos/http-signature-go"
)

func main() {
	// this is a test request
	r, err := http.NewRequest("POST", "http://example.com", bytes.NewBufferString("example.com"))
	if err != nil {
		panic(err)
	}

	var body []byte
	var digest string

	if r.Body != nil {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewBuffer(body))
	}
	keyId, keySecret := "key_id_1", "key_secret_1"

	paramter := httpsign.Parameter{
		KeyId:     httpsign.KeyId(keyId),
		Signature: "",
		Algorithm: "",
		Created:   0,
		Expires:   0,
		Headers: []string{
			httpsign.RequestTarget,
			httpsign.Date,
			httpsign.Nonce,
			httpsign.Digest,
		},
		Scheme: httpsign.SchemeSignature,
		Method: httpsign.SigningMethodHmacSha512,
		Key:    []byte(keySecret),
	}

	if len(body) > 0 {
		digest, err = httpsign.NewDigestUsingShared(paramter.Method).
			Sign(body, paramter.Key)
		if err != nil {
			panic(err)
		}
	}
	r.Header.Set(httpsign.Date, time.Now().UTC().Format(http.TimeFormat))
	r.Header.Set(httpsign.Nonce, "abcdefghijklmnopqrstuvwxyz123456") // 32位随机字符串
	r.Header.Set(httpsign.Digest, digest)
	err = paramter.MergerHeader(r)
	if err != nil {
		panic(err)
	}

	// Now: use the request, which carry http signature headers
	// _ = r
}
