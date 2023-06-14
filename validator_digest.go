package httpsign

import (
	"bytes"
	"io"
	"net/http"

	"github.com/things-go/httpsign/digest"
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
	headerDigest := r.Header.Get(DigestHeader)
	digest, err := v.calculateDigest(r)
	if err != nil {
		return err
	}
	if digest != headerDigest {
		return ErrDigestMismatch
	}
	return nil
}

func (v *DigestValidator) calculateDigest(r *http.Request) (string, error) {
	if r.ContentLength == 0 {
		return "", nil
	}
	// TODO: Read body using buffer to prevent using too much memory
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	return v.digest.Sign(body)
}
