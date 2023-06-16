package httpsign

// Keystone keyId mapping Metadata manager.
// Concurrently need to be supported.
type Keystone interface {
	// AddMetadata add metadata
	AddMetadata(KeyId, Metadata) error
	// DeleteMetadata delete metadata
	DeleteMetadata(KeyId) error
	// GetMetadata get metadata
	GetMetadata(KeyId) (Metadata, error)
}
