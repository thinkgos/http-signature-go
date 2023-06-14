package httpsign

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

const (
	AuthorizationHeader           = "Authorization"
	SignatureHeader               = "Signature"
	RequestTargetHeader           = "(request-target)"
	CreatedHeader                 = "(created)"
	ExpiresHeader                 = "(expires)"
	DateHeader                    = "date"
	DigestHeader                  = "digest"
	HostHeader                    = "host"
	authorizationHeaderInitPrefix = "Signature "
)

const (
	signingKeyId     = "keyId"
	signingSignature = "signature"
	signingAlgorithm = "algorithm"
	signingCreated   = "created"
	signingExpires   = "expires"
	signingHeaders   = "headers"
)

// Scheme support Signature or Authorization
type Scheme int

const (
	// Unspecified scheme, mean unlimited.
	SchemeUnspecified = iota
	// Authentication scheme.
	SchemeAuthentication
	// Signature http header scheme.
	SchemeSignature
)

// KeyId define type
type KeyId string

// Parameter contains basic info signature parameters.
type Parameter struct {
	// REQUIRED. The `keyId` field is an opaque string that the server can
	// use to look up the component they need to validate the signature.
	KeyId KeyId
	// REQUIRED. The `signature` parameter is a base 64 encoded digital signature.
	Signature string
	// RECOMMENDED. The `algorithm` parameter is used to specify the
	// signature string construction mechanism.
	Algorithm string
	// RECOMMENDED. The `created` field expresses when the signature was created.
	// The value MUST be a Unix timestamp integer value.
	Created int64
	// OPTIONAL. The `expires` field expresses when the signature ceases to
	// be valid. The value MUST be a Unix timestamp integer value.
	Expires int64
	// OPTIONAL. The `headers` parameter is used to specify the list of
	// HTTP headers included when generating the signature for the message.
	Headers []string

	// scheme support
	Scheme Scheme
	// signing method
	Method SigningMethod
	// signing method key.
	Key any
}

func (p *Parameter) MergerHeader(r *http.Request) error {
	if p.Method == nil || (p.Algorithm != "" && p.Algorithm != p.Method.Alg()) {
		return ErrAlgorithmMismatch
	}
	p.Algorithm = p.Method.Alg()
	signString := ConstructSignMessageFromRequest(r, p.Headers)
	signature, err := p.Method.Sign(signString, p.Key)
	if err != nil {
		return err
	}
	p.Signature = base64.StdEncoding.EncodeToString(signature)

	b := strings.Builder{}
	hd := SignatureHeader
	if p.Scheme == SchemeAuthentication {
		hd = AuthorizationHeader
		b.WriteString(authorizationHeaderInitPrefix)
	}
	b.WriteString(fmt.Sprintf(`keyId="%s",`, p.KeyId))
	b.WriteString(fmt.Sprintf(`algorithm="%s",`, p.Algorithm))
	if p.Created > 0 {
		b.WriteString(fmt.Sprintf(`created=%d,`, p.Created))
	}
	if p.Expires > 0 {
		b.WriteString(fmt.Sprintf(`expires=%d,`, p.Expires))
	}
	b.WriteString(fmt.Sprintf(`headers="%s",`, strings.Join(p.Headers, " ")))
	b.WriteString(fmt.Sprintf(`signature="%s"`, p.Signature))
	r.Header.Set(hd, b.String())
	return nil
}

func ConstructSignMessageFromRequest(r *http.Request, headers []string) string {
	b := strings.Builder{}
	for i, k := range headers {
		var v string
		switch k {
		case HostHeader:
			v = r.Host
		case RequestTargetHeader:
			v = fmt.Sprintf("%s %s", strings.ToLower(r.Method), r.URL.RequestURI())
		default:
			v = strings.Join(r.Header.Values(k), ", ")
		}
		k = strings.ToLower(k)
		v = strings.TrimSpace(v)
		if v == "" {
			v = " "
		}
		b.WriteString(fmt.Sprintf("%s: %s", k, v))
		if i < len(headers)-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}