package httpsign

import (
	"bytes"
	"io"
	"net/http"

	"github.com/thinkgos/http-signature-go/digest"
)

// DigestValidator checking digest in header match body
type DigestValidator struct {
	digest digest.Digest
}

// NewDigestValidator return pointer of new DigestValidator
func NewDigestValidator(digest digest.Digest) *DigestValidator {
	return &DigestValidator{digest: digest}
}

// Validate return error when checking digest match body
func (v *DigestValidator) Validate(r *http.Request, _ *Parameter) error {
	if r.ContentLength == 0 {
		return nil
	}
	headerDigest := r.Header.Get(Digest)

	// FIXME: using buffer to prevent using too much memory
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	digest, err := v.digest.Sign(body)
	if err != nil {
		return err
	}
	if digest != headerDigest {
		return ErrDigestMismatch
	}
	return nil
}
