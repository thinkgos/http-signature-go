package httpsign

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_DigestUsingShared_Sign(t *testing.T) {
	signingBytes := []byte("http signature!!")
	signingKey := []byte("http signing key!!")
	tests := []struct {
		name         string
		dd           *DigestUsingShared
		signingBytes []byte
		key          []byte
		wantSign     string
		wantErr      error
	}{
		{
			name:         "sha256 - success",
			dd:           NewDigestUsingShared(SigningMethodHmacSha256),
			signingBytes: signingBytes,
			key:          signingKey,
			wantSign:     "hmac-sha256=u3rJnV7cWSJxCavgWv3+Kne6EyHE43MgK/Vozywrqd8=",
			wantErr:      nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.dd.Sign(tt.signingBytes, tt.key)
			require.Equal(t, tt.wantErr, err)
			if err == nil {
				require.Equal(t, tt.wantSign, got)
			}
		})
	}
}

func Test_DigestUsingShared_Verify(t *testing.T) {
	signingBytes := []byte("http signature!!")
	signingKey := []byte("http signing key!!")
	tests := []struct {
		name         string
		dd           *DigestUsingShared
		signingBytes []byte
		sign         string
		key          []byte
		wantErr      error
	}{
		{
			name:         "sha256 - success",
			dd:           NewDigestUsingShared(SigningMethodHmacSha256),
			signingBytes: signingBytes,
			sign:         "hmac-sha256=u3rJnV7cWSJxCavgWv3+Kne6EyHE43MgK/Vozywrqd8=",
			key:          signingKey,
			wantErr:      nil,
		},
		{
			name:         "sha256 - invalid base64 encoding",
			dd:           NewDigestUsingShared(SigningMethodHmacSha256),
			signingBytes: signingBytes,
			sign:         "hmac-sha256=u3rJnV7cWSJxCavgWv3+Kne6EyHE43MgK/Vozywrqd8=x",
			key:          signingKey,
			wantErr:      ErrDigestMismatch,
		},
		{
			name:         "sha256 - incorrect signing",
			dd:           NewDigestUsingShared(SigningMethodHmacSha256),
			signingBytes: signingBytes,
			sign:         "hmac-sha256=HZcAQzdEnRzLPxrMIDTC047DDdDHr3/7U2aP4o3iRjM=",
			key:          signingKey,
			wantErr:      ErrDigestMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dd.Verify(tt.signingBytes, tt.sign, tt.key)
			require.Equal(t, tt.wantErr, err)
		})
	}
}
