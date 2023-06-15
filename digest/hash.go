package digest

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

// ErrHashUnavailable the requested hash function is unavailable
var ErrHashUnavailable = errors.New("the requested hash function is unavailable")

var (
	DigestHashMD5    = &DigestHash{"MD5", crypto.MD5}
	DigestHashSha1   = &DigestHash{"SHA1", crypto.SHA1}
	DigestHashSha256 = &DigestHash{"SHA256", crypto.SHA256}
	DigestHashSha384 = &DigestHash{"SHA384", crypto.SHA384}
	DigestHashSha512 = &DigestHash{"SHA512", crypto.SHA512}
)

type DigestHash struct {
	Name string
	Hash crypto.Hash
}

func (m *DigestHash) Alg() string { return m.Name }

func (m *DigestHash) Sign(p []byte) (string, error) {
	return m.SignReader(bytes.NewReader(p))
}

func (m *DigestHash) SignReader(r io.Reader) (string, error) {
	if !m.Hash.Available() {
		return "", ErrHashUnavailable
	}
	rd := bufio.NewReader(r)
	hasher := sha256.New()
	_, err := io.Copy(hasher, rd)
	if err != nil {
		return "", err
	}
	return m.Name + "=" + base64.StdEncoding.EncodeToString(hasher.Sum(nil)), nil
}

func (m *DigestHash) Verify(p []byte, sig string) error {
	return m.VerifyReader(bytes.NewReader(p), sig)
}

func (m *DigestHash) VerifyReader(r io.Reader, sig string) error {
	s, err := m.SignReader(r)
	if err != nil {
		return err
	}
	if s != sig {
		return ErrSignature
	}
	return nil
}
