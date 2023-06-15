package httpsign

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const (
	HeaderAuthorization = "Authorization"
	HeaderSignature     = "Signature"

	headerValueAuthorizationInitPrefix = "Signature "
)

const (
	Date          = "date"
	Digest        = "digest"
	Host          = "host"
	Nonce         = "nonce"
	ContentLength = "content-length"
	RequestTarget = "(request-target)"
	Created       = "(created)"
	Expires       = "(expires)"
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

	// inner values
	headerMap map[string]struct{}
}

// ContainsHeader returns true if headers contains header.
// NOTE: init inner headerMap use header when first called this function.
func (p *Parameter) ContainsHeader(header string) bool {
	if p.headerMap == nil {
		p.headerMap = make(map[string]struct{}, len(p.Headers))
		for _, hd := range p.Headers {
			p.headerMap[hd] = struct{}{}
		}
	}
	_, ok := p.headerMap[header]
	return ok
}

func (p *Parameter) MergerHeader(r *http.Request) error {
	if p.Method == nil || (p.Algorithm != "" && p.Algorithm != p.Method.Alg()) {
		return ErrAlgorithmMismatch
	}
	p.Algorithm = p.Method.Alg()
	signString := ConstructSignMessageFromRequest(r, p)
	signature, err := p.Method.Sign([]byte(signString), p.Key)
	if err != nil {
		return err
	}
	p.Signature = base64.StdEncoding.EncodeToString(signature)

	b := strings.Builder{}
	hd := HeaderSignature
	if p.Scheme == SchemeAuthentication {
		hd = HeaderAuthorization
		b.WriteString(headerValueAuthorizationInitPrefix)
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

func ConstructSignMessageFromRequest(r *http.Request, p *Parameter) string {
	b := strings.Builder{}
	for i, k := range p.Headers {
		var v string
		switch k {
		case Host:
			v = r.Host
		case RequestTarget:
			v = fmt.Sprintf("%s %s", strings.ToLower(r.Method), r.URL.RequestURI())
		case Created:
			v = strconv.FormatInt(p.Created, 10)
		case Expires:
			v = strconv.FormatInt(p.Expires, 10)
		default:
			v = strings.Join(r.Header.Values(k), ", ")
		}
		k = strings.ToLower(k)
		v = strings.TrimSpace(v)
		if v == "" {
			v = " "
		}
		b.WriteString(fmt.Sprintf("%s: %s", k, v))
		if i < len(p.Headers)-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}
