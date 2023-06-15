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
	minimumRequiredHeaders1 = []string{RequestTarget, Created}
	// if `algorithm` does start with `rsa`,`hmac`, or `ecdsa`
	minimumRequiredHeaders2 = []string{RequestTarget, Date}
)

// Metadata define key and algorithm that keyId use.
type Metadata struct {
	Scheme Scheme
	Alg    string
	Key    any
}

// Parser definition how to parse from http request.
type Parser struct {
	// validators: empty
	validators []Validator
	// minimumRequiredHeaders: empty
	// use minimumRequiredHeaders1, if `algorithm` does not start with `rsa`,`hmac`, or `ecdsa`.
	// use minimumRequiredHeaders2, if `algorithm` does start with `rsa`,`hmac`, or `ecdsa`.
	minimumRequiredHeaders []string
	// extractor: SignatureExtractor and AuthorizationSignatureExtractor.
	extractor Extractor
	// keystone: KeystoneMemory
	// hold keyId mapping Metadata.
	keystone Keystone
	// hold flow fields.
	mu              sync.RWMutex
	signingRegistry map[string]func() SigningMethod
}

// NewParser new parser instance.
// default value see Parser struct definition.
func NewParser(opts ...ParserOption) *Parser {
	p := &Parser{
		extractor: NewMultiExtractor(
			NewSignatureExtractor(HeaderSignature),
			NewAuthorizationSignatureExtractor(HeaderAuthorization),
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

func (p *Parser) ParseFromRequest(r *http.Request) (*Parameter, error) {
	s, scheme, err := p.extractor.Extract(r)
	if err != nil {
		return nil, err
	}
	results, err := parseSignatureValue(s)
	if err != nil {
		return nil, err
	}
	keyId, ok := results[signingKeyId]
	if !ok {
		return nil, ErrKeyIdMissing
	}
	signature, ok := results[signingSignature]
	if !ok {
		return nil, ErrSignatureMissing
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
	// headers to map
	headerMap := make(map[string]struct{}, len(headers))
	for _, hd := range headers {
		headerMap[hd] = struct{}{}
	}

	created := int64(0)
	if _, ok := headerMap[Created]; ok {
		if s := results[signingCreated]; s != "" {
			created, err = strconv.ParseInt(s, 10, 64)
			if err != nil {
				return nil, ErrCreatedInvalid
			}
		}
	}
	expires := int64(0)
	if _, ok := headerMap[Expires]; ok {
		if s := results[signingExpires]; s != "" {
			expires, err = strconv.ParseInt(s, 10, 64)
			if err != nil {
				return nil, ErrExpiresInvalid
			}
		}
	}
	return &Parameter{
		KeyId:     KeyId(keyId),
		Signature: signature,
		Algorithm: algorithm,
		Created:   created,
		Expires:   expires,
		Headers:   headers,
		Scheme:    scheme,
		Method:    nil,
		Key:       nil,
		headerMap: headerMap,
	}, nil
}

// Verify Parameter.
// return nil, if successful. then it will set Parameter signing Method and signing Method Key.
func (p *Parser) Verify(r *http.Request, param *Parameter) error {
	if !p.isMeetMinimumRequiredHeader(param) {
		return ErrMinimumRequiredHeader
	}
	metadata, err := p.GetMetadata(param.KeyId)
	if err != nil {
		return ErrKeyIdInvalid
	}
	if metadata.Alg != param.Algorithm {
		return ErrAlgorithmMismatch
	}
	if metadata.Scheme != SchemeUnspecified &&
		metadata.Scheme != param.Scheme {
		return ErrSchemeUnsupported
	}
	signingMethod := p.GetSigningMethod(param.Algorithm)
	if signingMethod == nil {
		return ErrAlgorithmUnsupported
	}

	sig, err := base64.StdEncoding.DecodeString(param.Signature)
	if err != nil {
		return ErrSignatureInvalid
	}
	signingString := ConstructSignMessageFromRequest(r, param)
	err = signingMethod.Verify([]byte(signingString), sig, metadata.Key)
	if err != nil {
		return err
	}
	param.Method = signingMethod
	param.Key = metadata.Key
	for _, v := range p.validators {
		if err := v.Validate(r, param); err != nil {
			return err
		}
	}
	return nil
}

// ParseVerify parse from http request, and then validate all parameters.
func (p *Parser) ParseVerify(r *http.Request) (Scheme, error) {
	param, err := p.ParseFromRequest(r)
	if err != nil {
		return SchemeUnspecified, err
	}
	return param.Scheme, p.Verify(r, param)
}

// isMeetMinimumRequiredHeader check if all server required header is in header list
// but implementers SHOULD at minimum include the `(request-target)` and
// `(created)` header fields if `algorithm` does not start with `rsa`,
// `hmac`, or `ecdsa`. Otherwise, `(request-target)` and `date` SHOULD
// be included in the signature.
func (p *Parser) isMeetMinimumRequiredHeader(param *Parameter) bool {
	minimumRequiredHeaders := p.minimumRequiredHeaders
	if len(p.minimumRequiredHeaders) == 0 {
		if isSpecifyAlg(param.Algorithm) {
			minimumRequiredHeaders = minimumRequiredHeaders2
		} else {
			minimumRequiredHeaders = minimumRequiredHeaders1
		}
	}
	for _, hd := range minimumRequiredHeaders {
		if !param.ContainsHeader(hd) {
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
