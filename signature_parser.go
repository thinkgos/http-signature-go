package httpsign

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/exp/slices"
)

// minimum include the `(request-target)` and`(created)` header fields
// if `algorithm` does not start with `rsa`,`hmac`, or `ecdsa`
// Otherwise, `(request-target)` and `date` SHOULD be included in the signature.
var (
	// if `algorithm` does not start with `rsa`,`hmac`, or `ecdsa`
	minimumRequiredHeaders1 = []string{RequestTargetHeader, CreatedHeader}
	// if `algorithm` does start with `rsa`,`hmac`, or `ecdsa`
	minimumRequiredHeaders2 = []string{RequestTargetHeader, DateHeader}
)

// Metadata define key and algorithm that keyId use.
type Metadata struct {
	Scheme Scheme
	Alg    string
	Key    any
}

type Parser struct {
	validators             []Validator
	validatorCreated       ValidatorTimestamp
	validatorExpires       ValidatorTimestamp
	minimumRequiredHeaders []string
	extractor              Extractor
	keystone               Keystone
	// hold flow fields.
	mu              sync.RWMutex
	signingRegistry map[string]func() SigningMethod
}

func NewParser(opts ...ParserOption) *Parser {
	p := &Parser{
		validatorCreated: NewCreatedValidator(),
		validatorExpires: NewExpiresValidator(),
		extractor: NewMultiExtractor(
			NewSignatureExtractor(SignatureHeader),
			NewAuthorizationSignatureExtractor(AuthorizationHeader),
		),
		keystone:        NewKeystoneMemory(),
		signingRegistry: make(map[string]func() SigningMethod),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// RegisterSigningMethod registers the "alg" name and a factory function for signing method.
func (p *Parser) RegisterSigningMethod(alg string, f func() SigningMethod) *Parser {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.signingRegistry[alg] = f
	return p
}

// GetSigningMethod retrieves a signing method from an "alg" string.
// Returns nil if alg not found.
func (p *Parser) GetSigningMethod(alg string) (method SigningMethod) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if f, ok := p.signingRegistry[alg]; ok {
		method = f()
	}
	return
}

// GetSigningMethodAlgorithms returns a list of add "alg" names
func (p *Parser) GetSigningMethodAlgorithms() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	algs := make([]string, 0, len(p.signingRegistry))
	for alg := range p.signingRegistry {
		algs = append(algs, alg)
	}
	return algs
}

// AddMetadata add keyId metadata.
func (p *Parser) AddMetadata(keyId KeyId, md Metadata) error {
	return p.keystone.AddMetadata(keyId, md)
}

// GetMetadata returns the keyId metadata.
func (p *Parser) GetMetadata(keyId KeyId) (Metadata, error) {
	return p.keystone.GetMetadata(keyId)
}

// DeleteMetadata delete the keyId metadata.
func (p *Parser) DeleteMetadata(keyId KeyId) error {
	return p.keystone.DeleteMetadata(keyId)
}

func (p *Parser) Parse(r *http.Request) (Scheme, error) {
	s, scheme, err := p.extractor.Extract(r)
	if err != nil {
		return scheme, err
	}
	results, err := parseSignatureValue(s)
	if err != nil {
		return scheme, err
	}
	keyId, ok := results[signingKeyId]
	if !ok {
		return scheme, ErrKeyIdMissing
	}
	signature, ok := results[signingSignature]
	if !ok {
		return scheme, ErrSignatureMissing
	}
	algorithm := results[signingAlgorithm]

	headerString, ok := results[signingHeaders]
	var headers []string
	if !ok || len(headerString) == 0 {
		if isSpecifyAlg(algorithm) {
			headers = slices.Clone(minimumRequiredHeaders2)
		} else {
			headers = slices.Clone(minimumRequiredHeaders1)
		}
	} else {
		headers = strings.Split(headerString, " ")
	}
	if !p.isMeetMinimumRequiredHeader(algorithm, headers) {
		return scheme, ErrMinimumRequiredHeader
	}
	created := int64(0)
	if slices.Contains(headers, CreatedHeader) {
		createdHeader, err := strconv.ParseInt(r.Header.Get(CreatedHeader), 10, 64)
		if err != nil {
			return scheme, ErrCreatedInvalid
		}
		if s := results[signingCreated]; s != "" {
			created, err = strconv.ParseInt(s, 10, 64)
			if err != nil {
				return scheme, ErrCreatedInvalid
			}
			if created != createdHeader {
				return scheme, ErrCreatedMismatch
			}
		}
		err = p.validatorCreated.ValidateTimestamp(created)
		if err != nil {
			return scheme, err
		}
	}
	expires := int64(0)
	if slices.Contains(headers, ExpiresHeader) {
		expiresHeader, err := strconv.ParseInt(r.Header.Get(ExpiresHeader), 10, 64)
		if err != nil {
			return scheme, ErrExpiresInvalid
		}
		if s := results[signingExpires]; s != "" {
			expires, err = strconv.ParseInt(s, 10, 64)
			if err != nil {
				return scheme, ErrExpiresInvalid
			}
			if expires != expiresHeader {
				return scheme, ErrExpiresMismatch
			}
		}
		err = p.validatorExpires.ValidateTimestamp(expires)
		if err != nil {
			return scheme, err
		}
	}

	metadata, err := p.GetMetadata(KeyId(keyId))
	if err != nil {
		return scheme, ErrKeyIdInvalid
	}
	if metadata.Alg != algorithm {
		return scheme, ErrAlgorithmMismatch
	}
	if metadata.Scheme != SchemeUnspecified &&
		metadata.Scheme != scheme {
		return scheme, ErrSchemeUnsupported
	}
	method := p.GetSigningMethod(algorithm)
	if method == nil {
		return scheme, ErrAlgorithmUnsupported
	}

	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return scheme, ErrSignatureInvalid
	}
	signingString := ConstructSignMessageFromRequest(r, headers)
	err = method.Verify(signingString, sig, metadata.Key)
	if err != nil {
		return scheme, err
	}
	parameter := &Parameter{
		KeyId:     KeyId(keyId),
		Signature: signature,
		Algorithm: algorithm,
		Created:   created,
		Expires:   expires,
		Headers:   headers,
		Scheme:    scheme,
		Method:    method,
		Key:       metadata.Key,
	}
	for _, v := range p.validators {
		if err := v.Validate(r, parameter); err != nil {
			return scheme, err
		}
	}
	return scheme, nil
}

// isMeetMinimumRequiredHeader check if all server required header is in header list
// but implementers SHOULD at minimum include the `(request-target)` and
// `(created)` header fields if `algorithm` does not start with `rsa`,
// `hmac`, or `ecdsa`. Otherwise, `(request-target)` and `date` SHOULD
// be included in the signature.
func (p *Parser) isMeetMinimumRequiredHeader(alg string, headers []string) bool {
	minimumRequiredHeaders := p.minimumRequiredHeaders
	if len(p.minimumRequiredHeaders) == 0 {
		if isSpecifyAlg(alg) {
			minimumRequiredHeaders = minimumRequiredHeaders2
		} else {
			minimumRequiredHeaders = minimumRequiredHeaders1
		}
	}
	mp := make(map[string]struct{}, len(headers))
	for _, h := range headers {
		mp[h] = struct{}{}
	}
	for _, h := range minimumRequiredHeaders {
		if _, ok := mp[h]; !ok {
			return false
		}
	}
	return true
}

// return true if `algorithm` start with `rsa`, `hmac`, or `ecdsa`.
func isSpecifyAlg(alg string) bool {
	return strings.HasPrefix(alg, "rsa") ||
		strings.HasPrefix(alg, "hmac") ||
		strings.HasPrefix(alg, "ecdsa")
}
