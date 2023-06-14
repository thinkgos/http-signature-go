package httpsign

import (
	"net/http"
	"time"
)

const maxTimeGap = 30 * time.Second // 30 secs

// DateValidator checking validate by time range
type DateValidator struct {
	// Gap is max time different between client submit timestamp
	// and server time that considered valid. The time precision is millisecond.
	Gap time.Duration
}

// NewDateValidator return DateValidator with default value (30 second)
func NewDateValidator() *DateValidator {
	return &DateValidator{
		Gap: maxTimeGap,
	}
}

// Validate return error when checking if header date is valid or not
func (v *DateValidator) Validate(r *http.Request, _ *Parameter) error {
	t, err := http.ParseTime(r.Header.Get(DateHeader))
	if err != nil {
		return ErrDateInvalid
	}
	st := time.Now()
	start, end := st.Add(-v.Gap), st.Add(v.Gap)
	if t.Before(start) || t.After(end) {
		return ErrDateNotInRange
	}
	return nil
}
