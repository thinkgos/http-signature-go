package httpsign

import (
	"time"
)

// CreatedValidator checking validate created range
type CreatedValidator struct {
	// Gap is max time different between client submit timestamp
	// and server time that considered valid. The time precision is seconds.
	Gap time.Duration
}

// NewCreatedValidator return CreatedValidator with default value (30 second)
func NewCreatedValidator() *CreatedValidator {
	return &CreatedValidator{
		Gap: maxTimeGap,
	}
}

// Validate return error when checking if header date is valid or not
func (v *CreatedValidator) ValidateTimestamp(created int64) error {
	st := time.Now().Unix()
	sec := int64(v.Gap / time.Second)
	if dt := st - created; dt < -sec || dt > sec {
		return ErrCreatedNotInRange
	}
	return nil
}
