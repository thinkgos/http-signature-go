package digest

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDigest_Hash(t *testing.T) {
	plainText := []byte("hello world!")
	t.Run("invalid signature", func(t *testing.T) {
		err := DigestHashSha256.Verify(plainText, "invalid hash")
		require.Equal(t, ErrSignature, err)
	})
	t.Run("hash", func(t *testing.T) {
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
			gotHash, err := tt.digest.Sign(plainText)
			require.Equal(t, tt.wantErr, err)
			if err == nil {
				err = tt.digest.Verify(plainText, gotHash)
				require.NoError(t, err)
			}
			gotHash, err = tt.digest.SignReader(bytes.NewReader(plainText))
			require.Equal(t, tt.wantErr, err)
			if err == nil {
				err = tt.digest.Verify(plainText, gotHash)
				require.NoError(t, err)
			}
		}
	})
}
