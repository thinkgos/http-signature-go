package digest

import (
	"errors"
	"io"
)

// ErrSignature the signature verify failure.
var ErrSignature = errors.New("the signature verify failure")

// Digest can be used sign an input.
// The sign is then usually base64 encoded.
type Digest interface {
	// returns the alg identifier for this digest.
	Alg() string
	// Returns nil if sign is valid,
	// value format always `algorithm=<encoded digest output with base64>`
	Sign(p []byte) (string, error)
	// same as Sign
	SignReader(r io.Reader) (string, error)
	// Returns nil if signature is valid
	Verify(p []byte, sig string) error
	// same as Verify
	VerifyReader(r io.Reader, sig string) error
}
