package httpsign

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEd25519_Sign_Verify(t *testing.T) {
	tests := []struct {
		name          string
		privateFile   string
		publicFile    string
		signingMethod SigningMethod
		signingString []byte
	}{
		{
			"EdDSA",
			"testdata/ed25519-private.pem",
			"testdata/ed25519-public.pem",
			SigningMethodEdDSA,
			[]byte("http signature!!"),
		},
	}
	for _, tt := range tests {
		require.Equal(t, tt.name, tt.signingMethod.Alg())
		privateKeyData, err := os.ReadFile(tt.privateFile)
		require.NoError(t, err)
		privateKey, err := ParseEdPrivateKeyFromPEM(privateKeyData)
		require.NoError(t, err)

		publicKeyData, err := os.ReadFile(tt.publicFile)
		require.NoError(t, err)
		publicKey, err := ParseEdPublicKeyFromPEM(publicKeyData)
		require.NoError(t, err)

		sig, err := tt.signingMethod.Sign(tt.signingString, privateKey)
		require.NoError(t, err)
		err = tt.signingMethod.Verify(tt.signingString, sig, publicKey)
		require.NoError(t, err)
	}
}

func TestEd25519(t *testing.T) {
	testSigningBytes := []byte("testEd25519")
	testSigningSig := []byte("testEd25519Sig")
	testInvalidKey := "invalidEd25519Key"

	// privateKeyData, _ := os.ReadFile("ed25519-private.pem")
	// privateKey, _ := ParseEdPrivateKeyFromPEM(privateKeyData)
	publicKeyData, _ := os.ReadFile("testdata/ed25519-public.pem")
	publicKey, _ := ParseEdPublicKeyFromPEM(publicKeyData)

	t.Run("invalid key type", func(t *testing.T) {
		_, err := SigningMethodEdDSA.Sign(testSigningBytes, testInvalidKey)
		require.ErrorIs(t, err, ErrKeyTypeInvalid)
		err = SigningMethodEdDSA.Verify(testSigningBytes, testSigningSig, testInvalidKey)
		require.ErrorIs(t, err, ErrKeyTypeInvalid)
	})
	t.Run("invalid signature", func(t *testing.T) {
		err := SigningMethodEdDSA.Verify(testSigningBytes, testSigningSig, publicKey)
		require.ErrorIs(t, err, ErrSignatureInvalid)
	})
}
