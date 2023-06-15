package httpsign

import (
	"errors"
	"net/http"
	"strings"
)

// Extractor is an interface for extracting a signature from a HTTP request.
// The Extract method should return a signature string, Scheme or an error.
// If no signature is present, you must return ErrNoSignatureInRequest.
type Extractor interface {
	Extract(*http.Request) (string, Scheme, error)
}

// SignatureExtractor is an extractor for finding a signature in a header.
type SignatureExtractor string

// NewSignatureExtractor new a signature extractor instance.
func NewSignatureExtractor(h string) SignatureExtractor {
	return SignatureExtractor(h)
}

func (h SignatureExtractor) Extract(r *http.Request) (string, Scheme, error) {
	v := r.Header.Get(string(h))
	if v != "" {
		return v, SchemeSignature, nil
	}
	return "", SchemeUnspecified, ErrNoSignatureInRequest
}

// AuthorizationSignatureExtractor is an extractor for finding a signature in a header,
// which the value has prefix `Signature `
type AuthorizationSignatureExtractor string

// NewAuthorizationSignatureExtractor new a signature extractor instance.
func NewAuthorizationSignatureExtractor(h string) AuthorizationSignatureExtractor {
	return AuthorizationSignatureExtractor(h)
}

func (h AuthorizationSignatureExtractor) Extract(r *http.Request) (string, Scheme, error) {
	s := r.Header.Get(string(h))
	if s != "" {
		after, b := strings.CutPrefix(s, headerValueAuthorizationInitPrefix)
		if b {
			return after, SchemeAuthentication, nil
		}
	}
	return "", SchemeUnspecified, ErrNoSignatureInRequest
}

// MultiExtractor tries Extractors in order until one returns a signature string or an error occurs.
type MultiExtractor []Extractor

// NewMultiExtractor new multiple extractor instance.
func NewMultiExtractor(es ...Extractor) MultiExtractor {
	return MultiExtractor(es)
}

func (e MultiExtractor) Extract(r *http.Request) (string, Scheme, error) {
	for _, extractor := range e {
		s, scheme, err := extractor.Extract(r)
		if s != "" {
			return s, scheme, nil
		} else if !errors.Is(err, ErrNoSignatureInRequest) {
			return "", scheme, err
		}
	}
	return "", SchemeUnspecified, ErrNoSignatureInRequest
}
