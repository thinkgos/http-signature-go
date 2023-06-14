package httpsign

import "net/http"

// Validator interface for checking if a request is valid or not
type Validator interface {
	Validate(*http.Request, *Parameter) error
}

// ValidateTimestamp interface for checking if a timestamp is valid or not
type ValidatorTimestamp interface {
	ValidateTimestamp(int64) error
}
