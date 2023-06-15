package httpsign

import (
	"net/http"
	"time"
)

// ExpiresValidator checking validate expires.
type ExpiresValidator struct {
	// Gap is max time different between client submit timestamp
	// and server time that considered valid. The time precision is second.
	Gap time.Duration
}

// NewCreatedValidator return ExpiresValidator with default value (30 second)
func NewExpiresValidator() *ExpiresValidator {
	return &ExpiresValidator{
		Gap: maxTimeGap,
	}
}

// Validate return error when checking if header `expires` is valid or not
func (v *ExpiresValidator) Validate(r *http.Request, p *Parameter) error {
	if p.ContainsHeader(Expires) {
		st := time.Now().Unix()
		sec := int64(v.Gap / time.Second)
		if p.Expires > st+sec {
			return ErrSignatureExpired
		}
	}
	return nil
}
