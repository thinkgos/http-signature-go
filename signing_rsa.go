package httpsign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

// SigningMethodRSA implements the RSA family of signing methods.
// Expects *rsa.PrivateKey for signing and *rsa.PublicKey for validation
type SigningMethodRSA struct {
	Name string
	Hash crypto.Hash
}

// Specific instances for rsa shaXXX
var (
	SigningMethodRsaSha256 = &SigningMethodRSA{"rsa-sha256", crypto.SHA256}
	SigningMethodRsaSha384 = &SigningMethodRSA{"rsa-sha384", crypto.SHA256}
	SigningMethodRsaSha512 = &SigningMethodRSA{"rsa-sha512", crypto.SHA512}
)

func (m *SigningMethodRSA) Alg() string { return m.Name }

// Verify implements token verification for the SigningMethod
// For this signing method, must be an *rsa.PublicKey structure.
func (m *SigningMethodRSA) Verify(signingBytes, sig []byte, key any) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return ErrKeyTypeInvalid
	}
	if !m.Hash.Available() {
		return ErrHashUnavailable
	}
	hasher := m.Hash.New()
	hasher.Write(signingBytes)
	err := rsa.VerifyPKCS1v15(rsaKey, m.Hash, hasher.Sum(nil), sig)
	if err != nil {
		return ErrSignatureInvalid
	}
	return nil
}

// Sign implements token signing for the SigningMethod
// For this signing method, must be an *rsa.PrivateKey structure.
func (m *SigningMethodRSA) Sign(signingBytes []byte, key any) ([]byte, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrKeyTypeInvalid
	}
	if !m.Hash.Available() {
		return nil, ErrHashUnavailable
	}

	hasher := m.Hash.New()
	hasher.Write(signingBytes)
	return rsa.SignPKCS1v15(rand.Reader, rsaKey, m.Hash, hasher.Sum(nil))
}
