package httpsign

import (
	"encoding/base64"
	"strings"
)

type DigestUsingShared struct {
	signingMethod SigningMethod
	confuseKey    func(any) any
}

func NewDigestUsingShared(signingMethod SigningMethod) *DigestUsingShared {
	return NewDigestUsingSharedWithConfuse(signingMethod, func(k any) any { return k })
}

func NewDigestUsingSharedWithConfuse(signingMethod SigningMethod, f func(k any) any) *DigestUsingShared {
	return &DigestUsingShared{
		signingMethod: signingMethod,
		confuseKey:    f,
	}
}

func (m *DigestUsingShared) Sign(signingBytes []byte, key any) (string, error) {
	b, err := m.signingMethod.Sign(signingBytes, m.confuseKey(key))
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
	err = m.signingMethod.Verify(signingBytes, sig, m.confuseKey(key))
	if err != nil {
		return ErrDigestMismatch
	}
	return nil
}
