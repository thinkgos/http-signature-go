package digest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDigest_Hash(t *testing.T) {
	plainText := []byte("hello world!")
	wantHashFunc := func(name string, h func() hash.Hash) string {
		hasher := h()
		hasher.Write(plainText)
		return name + "=" + base64.StdEncoding.EncodeToString(hasher.Sum(nil))
	}
	tests := []struct {
		name    string
		alg     string
		h       func() hash.Hash
		digest  Digest
		wantErr error
	}{
		{
			name:    "sha256",
			alg:     "SHA256",
			h:       sha256.New,
			digest:  DigestHashSha256,
			wantErr: nil,
		},
		{
			name:    "sha256",
			alg:     "SHA256",
			h:       sha256.New,
			digest:  &DigestHash{"SHA256", 255},
			wantErr: ErrHashUnavailable,
		},
	}
	for _, tt := range tests {
		require.Equal(t, tt.alg, tt.digest.Alg())
		wantHash := wantHashFunc(tt.alg, tt.h)
		gotHash, err := tt.digest.Sign(plainText)
		require.Equal(t, tt.wantErr, err)
		if err == nil {
			require.Equal(t, wantHash, gotHash)
		}
		gotHash, err = tt.digest.SignReader(bytes.NewReader(plainText))
		require.Equal(t, tt.wantErr, err)
		if err == nil {
			require.Equal(t, wantHash, gotHash)
		}
	}
}
