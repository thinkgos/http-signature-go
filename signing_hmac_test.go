package httpsign

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHmac_Sign_Verify(t *testing.T) {
	hmacTestSigningBytes := []byte("http signature!!")
	hmacTestKey, _ := os.ReadFile("testdata/hmac_key")
	tests := []struct {
		name          string
		signingMethod SigningMethod
		signingBytes  []byte
	}{
		{
			"hmac-sha256",
			SigningMethodHmacSha256,
			hmacTestSigningBytes,
		},
		{
			"hmac-sha384",
			SigningMethodHmacSha384,
			hmacTestSigningBytes,
		},
		{
			"hmac-sha512",
			SigningMethodHmacSha512,
			hmacTestSigningBytes,
		},
	}
	for _, tt := range tests {
		require.Equal(t, tt.name, tt.signingMethod.Alg())
		sig, err := tt.signingMethod.Sign(tt.signingBytes, hmacTestKey)
		require.NoError(t, err)
		err = tt.signingMethod.Verify(tt.signingBytes, sig, hmacTestKey)
		require.NoError(t, err)
	}
}

func TestHmac(t *testing.T) {
	testSigningBytes := []byte("testHmac")
	testSigningSig := []byte("testHmacSig")
	testInvalidKey := "invalidHmacKey"
	testValidKey := []byte("validHmacKey")

	t.Run("invalid key type", func(t *testing.T) {
		_, err := SigningMethodHmacSha256.Sign(testSigningBytes, testInvalidKey)
		require.ErrorIs(t, err, ErrKeyTypeInvalid)
		err = SigningMethodHmacSha256.Verify(testSigningBytes, testSigningSig, testInvalidKey)
		require.ErrorIs(t, err, ErrKeyTypeInvalid)
	})
	t.Run("hash unavailable", func(t *testing.T) {
		unavailableSigningMethod := SigningMethodHMAC{
			Name: "unavailable",
			Hash: 255,
		}
		_, err := unavailableSigningMethod.Sign(testSigningBytes, testValidKey)
		require.ErrorIs(t, err, ErrHashUnavailable)
		err = unavailableSigningMethod.Verify(testSigningBytes, testSigningSig, testValidKey)
		require.ErrorIs(t, err, ErrHashUnavailable)
	})
	t.Run("invalid signature", func(t *testing.T) {
		err := SigningMethodHmacSha256.Verify(testSigningBytes, testSigningSig, testValidKey)
		require.ErrorIs(t, err, ErrSignatureInvalid)
	})
}
