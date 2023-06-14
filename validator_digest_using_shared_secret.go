package httpsign

import (
	"bytes"
	"io"
	"net/http"
)

type DigestUsingSharedSecret struct{}

// NewDigestValidator return pointer of new DigestValidator
func NewDigestUsingSharedSecret() *DigestUsingSharedSecret {
	return &DigestUsingSharedSecret{}
}

// Validate return error when checking digest match body
func (v *DigestUsingSharedSecret) Validate(r *http.Request, p *Parameter) error {
	if r.ContentLength == 0 {
		return nil
	}
	headerDigest := r.Header.Get(DigestHeader)

	// FIXME: using buffer to prevent using too much memory
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	err = p.Method.Verify(body, []byte(headerDigest), p.Key)
	if err != nil {
		return ErrDigestMismatch
	}
	return nil
}
