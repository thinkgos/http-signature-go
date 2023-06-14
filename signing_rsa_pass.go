package httpsign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

// SigningMethodRSAPSS implements the rsa pss shaXXX family of signing methods signing methods
type SigningMethodRSAPSS struct {
	*SigningMethodRSA
	Options *rsa.PSSOptions
	// VerifyOptions is optional. If set overrides Options for rsa.VerifyPPS.
	// Used to accept tokens signed with rsa.PSSSaltLengthAuto.
	VerifyOptions *rsa.PSSOptions
}

// Specific instances for RS/PS and company.
var (
	SigningMethodRsaPssSha256 = &SigningMethodRSAPSS{
		SigningMethodRSA: &SigningMethodRSA{
			Name: "rsa-pss-sha256",
			Hash: crypto.SHA256,
		},
		Options: &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		},
		VerifyOptions: &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		},
	}
	SigningMethodRsaPssSha384 = &SigningMethodRSAPSS{
		SigningMethodRSA: &SigningMethodRSA{
			Name: "rsa-pss-sha384",
			Hash: crypto.SHA384,
		},
		Options: &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		},
		VerifyOptions: &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		},
	}
	SigningMethodRsaPssSha512 = &SigningMethodRSAPSS{
		SigningMethodRSA: &SigningMethodRSA{
			Name: "rsa-pss-sha512",
			Hash: crypto.SHA512,
		},
		Options: &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		},
		VerifyOptions: &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		},
	}
)

// Verify implements token verification for the SigningMethod.
// For this verify method, key must be an rsa.PublicKey struct
func (m *SigningMethodRSAPSS) Verify(signingString string, sig []byte, key any) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return ErrKeyTypeInvalid
	}
	if !m.Hash.Available() {
		return ErrHashUnavailable
	}
	opts := m.Options
	if m.VerifyOptions != nil {
		opts = m.VerifyOptions
	}
	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))
	err := rsa.VerifyPSS(rsaKey, m.Hash, hasher.Sum(nil), sig, opts)
	if err != nil {
		return ErrSignatureInvalid
	}
	return nil
}

// Sign implements token signing for the SigningMethod.
// For this signing method, key must be an rsa.PrivateKey struct
func (m *SigningMethodRSAPSS) Sign(signingString string, key any) ([]byte, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrKeyTypeInvalid
	}
	if !m.Hash.Available() {
		return nil, ErrHashUnavailable
	}
	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))
	return rsa.SignPSS(rand.Reader, rsaKey, m.Hash, hasher.Sum(nil), m.Options)
}
