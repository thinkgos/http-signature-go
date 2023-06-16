package httpsign

import (
	"encoding/base64"
	"strings"
)

type DigestUsingShared struct {
	signingMethod SigningMethod
}

func NewDigestUsingShared(signingMethod SigningMethod) *DigestUsingShared {
	return &DigestUsingShared{
		signingMethod: signingMethod,
	}
}

func (m *DigestUsingShared) Sign(signingBytes []byte, key any) (string, error) {
	b, err := m.signingMethod.Sign(signingBytes, key)
	if err != nil {
		return "", err
	}
	return m.signingMethod.Alg() + "=" + base64.StdEncoding.EncodeToString(b), nil
}

func (m *DigestUsingShared) Verify(signingBytes []byte, digestString string, key any) error {
	base64Sig := strings.TrimPrefix(digestString, m.signingMethod.Alg()+"=")
	sig, err := base64.StdEncoding.DecodeString(base64Sig)
	if err != nil {
		return ErrDigestMismatch
	}
	err = m.signingMethod.Verify(signingBytes, sig, key)
	if err != nil {
		return ErrDigestMismatch
	}
	return nil
}
