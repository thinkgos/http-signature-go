package httpsign

import (
	"bytes"
	"io"
	"net/http"
)

type DigestUsingSharedValidator struct {
	confuseKey func(any) any
}

// NewDigestValidator return pointer of new DigestValidator
func NewDigestUsingSharedValidator() *DigestUsingSharedValidator {
	return &DigestUsingSharedValidator{
		confuseKey: func(k any) any { return k },
	}
}

// NewDigestValidator return pointer of new DigestValidator
func NewDigestUsingSharedWithConfuseValidator(f func(k any) any) *DigestUsingSharedValidator {
	return &DigestUsingSharedValidator{
		confuseKey: f,
	}
}

// Validate return error when checking digest match body
func (v *DigestUsingSharedValidator) Validate(r *http.Request, p *Parameter) error {
	if r.ContentLength == 0 {
		return nil
	}

	// FIXME: using buffer to prevent using too much memory
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	headerDigest := r.Header.Get(Digest)
	return NewDigestUsingSharedWithConfuse(p.Method, v.confuseKey).
		Verify(body, headerDigest, p.Key)
}
