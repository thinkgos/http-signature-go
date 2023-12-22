# http-signature-go

Signing HTTP Messages implement base on [HTTP Signature](https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures)

[![GoDoc](https://godoc.org/github.com/thinkgos/http-signature-go?status.svg)](https://godoc.org/github.com/thinkgos/http-signature-go)
[![Go.Dev reference](https://img.shields.io/badge/go.dev-reference-blue?logo=go&logoColor=white)](https://pkg.go.dev/github.com/thinkgos/http-signature-go?tab=doc)
[![codecov](https://codecov.io/gh/thinkgos/http-signature-go/branch/main/graph/badge.svg?token=b5sf1VdK57)](https://codecov.io/gh/thinkgos/http-signature-go)
[![Tests](https://github.com/thinkgos/http-signature-go/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/thinkgos/http-signature-go/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/thinkgos/http-signature-go)](https://goreportcard.com/report/github.com/thinkgos/http-signature-go)
[![Licence](https://img.shields.io/github/license/thinkgos/http-signature-go)](https://raw.githubusercontent.com/thinkgos/http-signature-go/master/LICENSE)
[![Tag](https://img.shields.io/github/v/tag/thinkgos/http-signature-go)](https://github.com/thinkgos/http-signature-go/tags)

## Usage

### Installation

Use go get.

```bash
    go get github.com/thinkgos/http-signature-go
```

Then import the package into your own code.

```go
    import httpsign "github.com/thinkgos/http-signature-go"
```

### Example

### Encode

[embedmd]:# (examples/encoder.go go)
```go
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
```

### Decode

[embedmd]:# (examples/decoder.go go)
```go
//go:build decoder

package main

import (
	httpsign "github.com/thinkgos/http-signature-go"
)

func main() {
	keystone := httpsign.NewKeystoneMemory()

	httpSignParser := httpsign.NewParser(
		httpsign.WithMinimumRequiredHeaders([]string{
			httpsign.RequestTarget,
			httpsign.Date,
			httpsign.Nonce,
			httpsign.Digest,
		}),
		httpsign.WithSigningMethods(
			httpsign.SigningMethodHmacSha256.Alg(),
			func() httpsign.SigningMethod { return httpsign.SigningMethodHmacSha256 },
		),
		httpsign.WithSigningMethods(
			httpsign.SigningMethodHmacSha384.Alg(),
			func() httpsign.SigningMethod { return httpsign.SigningMethodHmacSha384 },
		),
		httpsign.WithSigningMethods(
			httpsign.SigningMethodHmacSha512.Alg(),
			func() httpsign.SigningMethod { return httpsign.SigningMethodHmacSha512 },
		),
		httpsign.WithValidators(
			httpsign.NewDigestUsingSharedValidator(),
			httpsign.NewDateValidator(),
		),
		httpsign.WithKeystone(keystone),
	)

	err := httpSignParser.AddMetadata(
		httpsign.KeyId("key_id_1"),
		httpsign.Metadata{
			Scheme: httpsign.SchemeSignature,
			Alg:    "hmac-sha512",
			Key:    []byte("key_secret_1"),
		},
	)
	if err != nil {
		panic(err)
	}
	err = httpSignParser.AddMetadata(
		httpsign.KeyId("key_id_2"),
		httpsign.Metadata{
			Scheme: httpsign.SchemeSignature,
			Alg:    "hmac-sha512",
			Key:    []byte("key_secret_2"),
		},
	)
	if err != nil {
		panic(err)
	}

	// parser http.Request
	// httpSignParser.ParseFromRequest() and httpSignParser.Verify
	// or
	// httpSignParser.ParseVerify()
}
```

### Encode/Decode

[embedmd]:# (examples/encoder_decoder.go go)
```go
package main

import (
	"context"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"time"

	httpsign "github.com/thinkgos/http-signature-go"
)

// mock interface always return true
type timeAlwaysValid struct{}

func (v *timeAlwaysValid) Validate(r *http.Request, _ *httpsign.Parameter) error { return nil }

func main() {
	//* encoder

	r, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	if err != nil {
		panic(err)
	}

	p := &httpsign.Parameter{
		KeyId:     "key_id_1",
		Signature: "",
		Algorithm: "",
		Created:   time.Now().Add(-time.Hour).UTC().Unix(),
		Expires:   0,
		Headers:   []string{httpsign.RequestTarget, httpsign.Created, httpsign.Host},
		Scheme:    httpsign.SchemeSignature,
		Method:    httpsign.SigningMethodHmacSha256,
		Key:       []byte("1234"),
	}

	wantCreatedHeader := strconv.FormatInt(p.Created, 10)
	r.Header.Set(httpsign.Created, wantCreatedHeader)
	err = p.MergerHeader(r)
	if err != nil {
		panic(err)
	}

	//* decoder

	// validate created always valid
	parser := httpsign.NewParser(
		httpsign.WithMinimumRequiredHeaders([]string{httpsign.RequestTarget, httpsign.Created, httpsign.Host}),
		httpsign.WithSigningMethods(httpsign.SigningMethodHmacSha256.Alg(), func() httpsign.SigningMethod { return httpsign.SigningMethodHmacSha256 }),
		httpsign.WithValidators(&timeAlwaysValid{}),
	)
	err = parser.AddMetadata("key_id_1", httpsign.Metadata{
		Scheme: httpsign.SchemeUnspecified,
		Alg:    httpsign.SigningMethodHmacSha256.Alg(),
		Key:    []byte("1234"),
	})
	if err != nil {
		panic(err)
	}
	// parser http.Request

	// use httpSignParser.ParseFromRequest() and httpSignParser.Verify
	gotParam, err := parser.ParseFromRequest(r)
	if err != nil {
		panic(err)
	}
	if p.KeyId != gotParam.KeyId ||
		p.Signature != gotParam.Signature ||
		p.Algorithm != gotParam.Algorithm ||
		p.Created != gotParam.Created ||
		p.Expires != gotParam.Expires ||
		!slices.Equal(p.Headers, gotParam.Headers) ||
		p.Scheme != gotParam.Scheme {
		panic("param miss match")
	}
	err = parser.Verify(r, gotParam)
	if err != nil {
		panic(err)
	}
	if p.Method != gotParam.Method ||
		!reflect.DeepEqual(p.Key, gotParam.Key) ||
		p.Scheme != gotParam.Scheme {
		panic("param miss match")
	}
	// or

	// use httpSignParser.ParseVerify()
	gotScheme, err := parser.ParseVerify(r)
	if err != nil {
		panic(err)
	}
	if gotScheme != p.Scheme {
		panic("schema miss match")
	}
}
```

## License

This project is under MIT License. See the [LICENSE](LICENSE) file for the full license text.
