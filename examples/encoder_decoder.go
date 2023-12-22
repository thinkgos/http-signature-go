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
