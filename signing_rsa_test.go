package httpsign

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRsa_Sign_Verify(t *testing.T) {
	privateKeyData, _ := os.ReadFile("testdata/sample_key")
	privateKey, _ := ParseRSAPrivateKeyFromPEM(privateKeyData)
	publicKeyData, _ := os.ReadFile("testdata/sample_key.pub")
	publicKey, _ := ParseRSAPublicKeyFromPEM(publicKeyData)

	rsaSigningBytes := []byte("http signature!!")
	tests := []struct {
		name          string
		signingMethod SigningMethod
		signingString []byte
	}{
		{
			"rsa-sha256",
			SigningMethodRsaSha256,
			rsaSigningBytes,
		},
		{
			"rsa-sha384",
			SigningMethodRsaSha384,
			rsaSigningBytes,
		},
		{
			"rsa-sha512",
			SigningMethodRsaSha512,
			rsaSigningBytes,
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

func TestRsa(t *testing.T) {
	testSigningBytes := []byte("testRsa")
	testSigningSig := []byte("testRsaSig")
	testInvalidKey := "invalidRsaKey"

	privateKeyData, _ := os.ReadFile("testdata/sample_key")
	privateKey, _ := ParseRSAPrivateKeyFromPEM(privateKeyData)
	publicKeyData, _ := os.ReadFile("testdata/sample_key.pub")
	publicKey, _ := ParseRSAPublicKeyFromPEM(publicKeyData)

	t.Run("invalid key type", func(t *testing.T) {
		_, err := SigningMethodRsaSha256.Sign(testSigningBytes, testInvalidKey)
		require.ErrorIs(t, err, ErrKeyTypeInvalid)
		err = SigningMethodRsaSha256.Verify(testSigningBytes, testSigningSig, testInvalidKey)
		require.ErrorIs(t, err, ErrKeyTypeInvalid)
	})
	t.Run("hash unavailable", func(t *testing.T) {
		unavailableSigningMethod := SigningMethodRSA{
			Name: "unavailable",
			Hash: 255,
		}
		_, err := unavailableSigningMethod.Sign(testSigningBytes, privateKey)
		require.ErrorIs(t, err, ErrHashUnavailable)
		err = unavailableSigningMethod.Verify(testSigningBytes, testSigningSig, publicKey)
		require.ErrorIs(t, err, ErrHashUnavailable)
	})
	t.Run("invalid signature", func(t *testing.T) {
		err := SigningMethodRsaSha256.Verify(testSigningBytes, testSigningSig, publicKey)
		require.ErrorIs(t, err, ErrSignatureInvalid)
	})
}

func TestRSAKeyParsing(t *testing.T) {
	key, _ := os.ReadFile("testdata/sample_key")
	secureKey, _ := os.ReadFile("testdata/privateSecure.pem")
	pubKey, _ := os.ReadFile("testdata/sample_key.pub")
	badKey := []byte("All your base are belong to key")

	randomKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("Failed to generate RSA private key: %v", err)
	}

	publicKeyBytes := x509.MarshalPKCS1PublicKey(&randomKey.PublicKey)
	pkcs1Buffer := new(bytes.Buffer)
	if err = pem.Encode(pkcs1Buffer, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: publicKeyBytes}); err != nil {
		t.Errorf("Failed to encode public pem: %v", err)
	}

	// Test parsePrivateKey
	if _, e := ParseRSAPrivateKeyFromPEM(key); e != nil {
		t.Errorf("Failed to parse valid private key: %v", e)
	}
	if k, e := ParseRSAPrivateKeyFromPEM(pubKey); e == nil {
		t.Errorf("Parsed public key as valid private key: %v", k)
	}
	if k, e := ParseRSAPrivateKeyFromPEM(badKey); e == nil {
		t.Errorf("Parsed invalid key as valid private key: %v", k)
	}
	if _, e := ParseRSAPrivateKeyFromPEMWithPassword(secureKey, "password"); e != nil {
		t.Errorf("Failed to parse valid private key with password: %v", e)
	}
	if k, e := ParseRSAPrivateKeyFromPEMWithPassword(secureKey, "123132"); e == nil {
		t.Errorf("Parsed private key with invalid password %v", k)
	}

	// Test parsePublicKey
	if _, e := ParseRSAPublicKeyFromPEM(pubKey); e != nil {
		t.Errorf("Failed to parse valid public key: %v", e)
	}
	if k, e := ParseRSAPublicKeyFromPEM(key); e == nil {
		t.Errorf("Parsed private key as valid public key: %v", k)
	}
	if k, e := ParseRSAPublicKeyFromPEM(badKey); e == nil {
		t.Errorf("Parsed invalid key as valid private key: %v", k)
	}
	if _, err := ParseRSAPublicKeyFromPEM(pkcs1Buffer.Bytes()); err != nil {
		t.Errorf("failed to parse RSA public key: %v", err)
	}
}
