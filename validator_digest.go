package httpsign

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
)

// DigestValidator checking digest in header match body
type DigestValidator struct{}

// NewDigestValidator return pointer of new DigestValidator
func NewDigestValidator() *DigestValidator {
	return &DigestValidator{}
}

// Validate return error when checking digest match body
func (v *DigestValidator) Validate(r *http.Request, _ *Parameter) error {
	headerDigest := r.Header.Get(DigestHeader)
	digest, err := calculateDigest(r)
	if err != nil {
		return err
	}
	if digest != headerDigest {
		return ErrDigestMismatch
	}
	return nil
}

func calculateDigest(r *http.Request) (string, error) {
	if r.ContentLength == 0 {
		return "", nil
	}
	// TODO: Read body using buffer to prevent using too much memory
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	h := sha256.New()
	h.Write(body)
	if err != nil {
		return "", err
	}
	digest := fmt.Sprintf("SHA-256=%s", base64.StdEncoding.EncodeToString(h.Sum(nil)))
	return digest, nil
}
