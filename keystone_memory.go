package httpsign

import (
	"sync"
)

var _ Keystone = (*KeystoneMemory)(nil)

// KeystoneMemory memory keystone
type KeystoneMemory struct {
	mu    sync.RWMutex
	store map[KeyId]Metadata
}

// NewKeystoneMemory new memory keystone
func NewKeystoneMemory() *KeystoneMemory {
	return &KeystoneMemory{
		store: make(map[KeyId]Metadata),
	}
}

// AddMetadata implements Keystone.
func (k *KeystoneMemory) AddMetadata(keyId KeyId, md Metadata) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.store[keyId] = md
	return nil
}

// GetMetadata implements Keystone.
func (k *KeystoneMemory) GetMetadata(keyId KeyId) (Metadata, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	md, ok := k.store[keyId]
	if !ok {
		return md, ErrKeyIdInvalid
	}
	return md, nil
}

// DeleteMetadata implements Keystone.
func (k *KeystoneMemory) DeleteMetadata(keyId KeyId) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.store, keyId)
	return nil
}
