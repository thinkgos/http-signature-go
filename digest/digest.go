package digest

import "io"

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
}
