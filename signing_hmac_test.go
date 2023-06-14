package httpsign

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHmac_Sign_Verify(t *testing.T) {
	hmacTestKey, _ := os.ReadFile("testdata/hmac_key")
	tests := []struct {
		name          string
		signingMethod SigningMethod
		signingString string
	}{
		{
			"hmac-sha256",
			SigningMethodHmacSha256,
			"http signature!!",
		},
		{
			"hmac-sha384",
			SigningMethodHmacSha384,
			"http signature!!",
		},
		{
			"hmac-sha512",
			SigningMethodHmacSha512,
			"http signature!!",
		},
	}
	for _, tt := range tests {
		require.Equal(t, tt.name, tt.signingMethod.Alg())
		sig, err := tt.signingMethod.Sign(tt.signingString, hmacTestKey)
		require.NoError(t, err)
		err = tt.signingMethod.Verify(tt.signingString, sig, hmacTestKey)
		require.NoError(t, err)
	}
}

func TestHmac(t *testing.T) {
	testSigningString := "testHmac"
	testSigningSig := []byte("testHmacSig")
	testInvalidKey := "invalidHmacKey"
	testValidKey := []byte("validHmacKey")

	t.Run("invalid key type", func(t *testing.T) {
		_, err := SigningMethodHmacSha256.Sign(testSigningString, testInvalidKey)
		require.ErrorIs(t, err, ErrKeyTypeInvalid)
		err = SigningMethodHmacSha256.Verify(testSigningString, testSigningSig, testInvalidKey)
		require.ErrorIs(t, err, ErrKeyTypeInvalid)
	})
	t.Run("hash unavailable", func(t *testing.T) {
		unavailableSigningMethod := SigningMethodHMAC{
			Name: "unavailable",
			Hash: 255,
		}
		_, err := unavailableSigningMethod.Sign(testSigningString, testValidKey)
		require.ErrorIs(t, err, ErrHashUnavailable)
		err = unavailableSigningMethod.Verify(testSigningString, testSigningSig, testValidKey)
		require.ErrorIs(t, err, ErrHashUnavailable)
	})
	t.Run("invalid signature", func(t *testing.T) {
		err := SigningMethodHmacSha256.Verify(testSigningString, testSigningSig, testValidKey)
		require.ErrorIs(t, err, ErrSignatureInvalid)
	})
}
