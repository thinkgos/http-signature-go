package httpsign

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECDSA_Sign_Verify(t *testing.T) {
	ecdsaSigningBytes := []byte("http signature!!")
	tests := []struct {
		name          string
		privateFile   string
		publicFile    string
		signingMethod SigningMethod
		signingString []byte
	}{
		{
			"ecdsa-sha256",
			"testdata/ec256-private.pem",
			"testdata/ec256-public.pem",
			SigningMethodEcdsaSha256,
			ecdsaSigningBytes,
		},
		{
			"ecdsa-sha384",
			"testdata/ec384-private.pem",
			"testdata/ec384-public.pem",
			SigningMethodEcdsaSha384,
			ecdsaSigningBytes,
		},
		{
			"ecdsa-sha512",
			"testdata/ec512-private.pem",
			"testdata/ec512-public.pem",
			SigningMethodEcdsaSha512,
			ecdsaSigningBytes,
		},
	}

	for _, tt := range tests {
		require.Equal(t, tt.name, tt.signingMethod.Alg())
		privateKeyData, err := os.ReadFile(tt.privateFile)
		require.NoError(t, err)
		privateKey, err := ParseECPrivateKeyFromPEM(privateKeyData)
		require.NoError(t, err)

		publicKeyData, err := os.ReadFile(tt.publicFile)
		require.NoError(t, err)
		publicKey, err := ParseECPublicKeyFromPEM(publicKeyData)
		require.NoError(t, err)

		sig, err := tt.signingMethod.Sign(tt.signingString, privateKey)
		require.NoError(t, err)
		err = tt.signingMethod.Verify(tt.signingString, sig, privateKey.Public())
		require.NoError(t, err)
		err = tt.signingMethod.Verify(tt.signingString, sig, publicKey)
		require.NoError(t, err)
	}
}

func TestECDSA(t *testing.T) {
	testSigningBytes := []byte("testEcdsa")
	testInvalidSigningSig := []byte("testSig")
	testInvalidKey := "invalidEcdsaKey"
	testValidLenSigningSig := []byte(strings.Repeat("a", 64))

	privateKeyData, _ := os.ReadFile("testdata/ec256-private.pem")
	privateKey, _ := ParseECPrivateKeyFromPEM(privateKeyData)
	publicKeyData, _ := os.ReadFile("testdata/ec256-public.pem")
	publicKey, _ := ParseECPublicKeyFromPEM(publicKeyData)

	t.Run("invalid key type", func(t *testing.T) {
		_, err := SigningMethodEcdsaSha256.Sign(testSigningBytes, testInvalidKey)
		require.ErrorIs(t, err, ErrKeyTypeInvalid)
		err = SigningMethodEcdsaSha256.Verify(testSigningBytes, testInvalidSigningSig, testInvalidKey)
		require.ErrorIs(t, err, ErrKeyTypeInvalid)
	})
	t.Run("invalid sig len", func(t *testing.T) {
		err := SigningMethodEcdsaSha256.Verify(testSigningBytes, testInvalidSigningSig, publicKey)
		require.ErrorIs(t, err, ErrSignatureInvalid)
	})
	t.Run("hash unavailable", func(t *testing.T) {
		unavailableSigningMethod := SigningMethodECDSA{
			Name:      "unavailable",
			Hash:      255,
			KeySize:   32,
			CurveBits: 256,
		}
		_, err := unavailableSigningMethod.Sign(testSigningBytes, privateKey)
		require.ErrorIs(t, err, ErrHashUnavailable)
		_ = testValidLenSigningSig
		err = unavailableSigningMethod.Verify(testSigningBytes, testValidLenSigningSig, publicKey)
		require.ErrorIs(t, err, ErrHashUnavailable)
	})
	t.Run("invalid signature", func(t *testing.T) {
		err := SigningMethodEcdsaSha256.Verify(testSigningBytes, testInvalidSigningSig, publicKey)
		require.ErrorIs(t, err, ErrSignatureInvalid)
	})
}
