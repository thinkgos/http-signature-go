package httpsign

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRSAPSS_Sign_Verify(t *testing.T) {
	privateKeyData, _ := os.ReadFile("testdata/sample_key")
	privateKey, err := ParseRSAPrivateKeyFromPEM(privateKeyData)
	if err != nil {
		t.Errorf("Unable to parse RSA private key: %v", err)
	}

	publicKeyData, _ := os.ReadFile("testdata/sample_key.pub")
	publicKey, err := ParseRSAPublicKeyFromPEM(publicKeyData)
	if err != nil {
		t.Errorf("Unable to parse RSA public key: %v", err)
	}

	tests := []struct {
		name          string
		signingMethod SigningMethod
		signingString string
	}{
		{
			"rsa-pss-sha256",
			SigningMethodRsaPssSha256,
			"http signature!!",
		},
		{
			"rsa-pss-sha384",
			SigningMethodRsaPssSha384,
			"http signature!!",
		},
		{
			"rsa-pss-sha512",
			SigningMethodRsaPssSha512,
			"http signature!!",
		},
	}

	for _, tt := range tests {
		require.Equal(t, tt.name, tt.signingMethod.Alg())
		sig, err := tt.signingMethod.Sign(tt.signingString, privateKey)
		require.NoError(t, err)
		err = tt.signingMethod.Verify(tt.signingString, sig, publicKey)
		require.NoError(t, err)
	}
}

func TestRsaPss(t *testing.T) {
	testSigningString := "testRsaPss"
	testSigningSig := []byte("testRsaPssSig")
	testInvalidKey := "invalidKey"

	privateKeyData, _ := os.ReadFile("testdata/sample_key")
	privateKey, _ := ParseRSAPrivateKeyFromPEM(privateKeyData)
	publicKeyData, _ := os.ReadFile("testdata/sample_key.pub")
	publicKey, _ := ParseRSAPublicKeyFromPEM(publicKeyData)

	t.Run("invalid key type", func(t *testing.T) {
		_, err := SigningMethodRsaPssSha256.Sign(testSigningString, testInvalidKey)
		require.ErrorIs(t, err, ErrKeyTypeInvalid)
		err = SigningMethodRsaPssSha256.Verify(testSigningString, testSigningSig, testInvalidKey)
		require.ErrorIs(t, err, ErrKeyTypeInvalid)
	})
	t.Run("hash unavailable", func(t *testing.T) {
		unavailableSigningMethod := SigningMethodRSAPSS{
			SigningMethodRSA: &SigningMethodRSA{
				Name: "unavailable",
				Hash: 255,
			},
		}
		_, err := unavailableSigningMethod.Sign(testSigningString, privateKey)
		require.ErrorIs(t, err, ErrHashUnavailable)
		err = unavailableSigningMethod.Verify(testSigningString, testSigningSig, publicKey)
		require.ErrorIs(t, err, ErrHashUnavailable)
	})
	t.Run("invalid signature", func(t *testing.T) {
		err := SigningMethodRsaPssSha256.Verify(testSigningString, testSigningSig, publicKey)
		require.ErrorIs(t, err, ErrSignatureInvalid)
	})
}
