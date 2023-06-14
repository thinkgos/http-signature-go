package httpsign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
)

// SigningMethodECDSA implements the ECDSA family of signing methods.
// Expects *ecdsa.PrivateKey for signing and *ecdsa.PublicKey for verification
type SigningMethodECDSA struct {
	Name      string
	Hash      crypto.Hash
	KeySize   int
	CurveBits int
}

// Specific instance ecdsa.
var (
	SigningMethodEcdsaSha256 = &SigningMethodECDSA{"ecdsa-sha256", crypto.SHA256, 32, 256}
	SigningMethodEcdsaSha384 = &SigningMethodECDSA{"ecdsa-sha384", crypto.SHA384, 48, 384}
	SigningMethodEcdsaSha512 = &SigningMethodECDSA{"ecdsa-sha512", crypto.SHA512, 66, 521}
)

func (m *SigningMethodECDSA) Alg() string {
	return m.Name
}

// Verify implements token verification for the SigningMethod.
// For this verify method, key must be an ecdsa.PublicKey struct
func (m *SigningMethodECDSA) Verify(signingString string, sig []byte, key any) error {
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return ErrKeyTypeInvalid
	}
	if len(sig) != 2*m.KeySize {
		return ErrSignatureInvalid
	}

	r := big.NewInt(0).SetBytes(sig[:m.KeySize])
	s := big.NewInt(0).SetBytes(sig[m.KeySize:])

	if !m.Hash.Available() {
		return ErrHashUnavailable
	}
	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))
	if verifystatus := ecdsa.Verify(ecdsaKey, hasher.Sum(nil), r, s); verifystatus {
		return nil
	}
	return ErrSignatureInvalid
}

// Sign implements token signing for the SigningMethod.
// For this signing method, key must be an ecdsa.PrivateKey struct
func (m *SigningMethodECDSA) Sign(signingString string, key any) ([]byte, error) {
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrKeyTypeInvalid
	}
	if !m.Hash.Available() {
		return nil, ErrHashUnavailable
	}

	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))
	// Sign the string and return r, s
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hasher.Sum(nil))
	if err != nil {
		return nil, err
	}

	curveBits := ecdsaKey.Curve.Params().BitSize
	if m.CurveBits != curveBits {
		return nil, ErrKeyInvalid
	}

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}
	// We serialize the outputs (r and s) into big-endian byte arrays
	// padded with zeros on the left to make sure the sizes work out.
	// Output must be 2*keyBytes long.
	out := make([]byte, 2*keyBytes)
	r.FillBytes(out[0:keyBytes]) // r is assigned to the first half of output.
	s.FillBytes(out[keyBytes:])  // s is assigned to the second half of output.
	return out, nil
}
