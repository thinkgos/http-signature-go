package digest

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

var plainText = []byte("hello world!")

func TestDigest_Sign_Verify(t *testing.T) {
	t.Run("invalid signature", func(t *testing.T) {
		err := DigestHashSha256.Verify(plainText, "invalid hash")
		require.Equal(t, ErrSignature, err)
	})

	t.Run("sign", func(t *testing.T) {
		tests := []struct {
			name     string
			alg      string
			digest   Digest
			wantSign string
			wantErr  error
		}{
			{
				name:     "unavailable",
				alg:      "SHA256",
				digest:   &DigestHash{"SHA256", 255},
				wantSign: "",
				wantErr:  ErrHashUnavailable,
			},
			{
				name:     "MD5",
				alg:      "MD5",
				digest:   DigestHashMD5,
				wantSign: "MD5=/D/5joxqDTCH1RXARz+Gdw==",
				wantErr:  nil,
			},
			{
				name:     "SHA256",
				alg:      "SHA256",
				digest:   DigestHashSha256,
				wantSign: "SHA256=dQnlvaDHYtK6x/kNdYtbImP6Acy8VCq1498WO+CObKk=",
				wantErr:  nil,
			},
		}
		for _, tt := range tests {
			require.Equal(t, tt.alg, tt.digest.Alg())
			gotHash, err := tt.digest.Sign(plainText)
			require.Equal(t, tt.wantErr, err)
			require.Equal(t, tt.wantSign, gotHash)
			gotHash, err = tt.digest.SignReader(bytes.NewReader(plainText))
			require.Equal(t, tt.wantErr, err)
			require.Equal(t, tt.wantSign, gotHash)
		}
	})

	t.Run("sign verify", func(t *testing.T) {
		tests := []struct {
			name    string
			alg     string
			digest  Digest
			wantErr error
		}{
			{
				name:    "MD5",
				alg:     "MD5",
				digest:  DigestHashMD5,
				wantErr: nil,
			},
			{
				name:    "SHA1",
				alg:     "SHA1",
				digest:  DigestHashSha1,
				wantErr: nil,
			},
			{
				name:    "SHA256",
				alg:     "SHA256",
				digest:  DigestHashSha256,
				wantErr: nil,
			},
			{
				name:    "SHA384",
				alg:     "SHA384",
				digest:  DigestHashSha384,
				wantErr: nil,
			},
			{
				name:    "SHA512",
				alg:     "SHA512",
				digest:  DigestHashSha512,
				wantErr: nil,
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
