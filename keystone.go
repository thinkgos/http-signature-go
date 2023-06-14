package httpsign

type Keystone interface {
	AddMetadata(KeyId, Metadata) error
	DeleteMetadata(KeyId) error
	GetMetadata(KeyId) (Metadata, error)
}
