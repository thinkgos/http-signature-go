package httpsign

// SigningMethod can be used add new methods for signing or verifying signature. It
// takes a decoded signature as an input in the Verify function and produces a
// signature in Sign. The signature is then usually base64 encoded as part of a
// Signature.
type SigningMethod interface {
	// returns the alg identifier for this method.
	Alg() string
	// Returns nil if signature is valid
	Verify(signingBytes []byte, sig []byte, key any) error
	// Returns signature or error
	Sign(signingBytes []byte, key any) ([]byte, error)
}
