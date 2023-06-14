package httpsign

import (
	"crypto"
	"crypto/hmac"
)

// Specific instances for hmac shaXXX
var (
	SigningMethodHmacSha256 = &SigningMethodHMAC{"hmac-sha256", crypto.SHA256}
	SigningMethodHmacSha384 = &SigningMethodHMAC{"hmac-sha384", crypto.SHA384}
	SigningMethodHmacSha512 = &SigningMethodHMAC{"hmac-sha512", crypto.SHA512}
)

// SigningMethodHMAC implements the HMAC-SHA family of signing methods.
// Expects key type of []byte for both signing and validation
type SigningMethodHMAC struct {
	Name string
	Hash crypto.Hash
}

func (m *SigningMethodHMAC) Alg() string { return m.Name }

// Verify implements verification for the SigningMethod. Returns nil if
// the signature is valid. Key must be []byte.
func (m *SigningMethodHMAC) Verify(signingBytes, sig []byte, key any) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return ErrKeyTypeInvalid
	}
	if !m.Hash.Available() {
		return ErrHashUnavailable
	}

	// This signing method is symmetric, so we validate the signature
	// by reproducing the signature from the signing string and key, then
	// comparing that against the provided signature.
	hasher := hmac.New(m.Hash.New, keyBytes)
	hasher.Write(signingBytes)
	if !hmac.Equal(sig, hasher.Sum(nil)) {
		return ErrSignatureInvalid
	}
	// No validation errors.  Signature is good.
	return nil
}

// Sign implements signing for the SigningMethod. Key must be []byte.
func (m *SigningMethodHMAC) Sign(signingBytes []byte, key any) ([]byte, error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		return nil, ErrKeyTypeInvalid
	}
	if !m.Hash.Available() {
		return nil, ErrHashUnavailable
	}
	hasher := hmac.New(m.Hash.New, keyBytes)
	hasher.Write(signingBytes)
	return hasher.Sum(nil), nil
}
