//go:build decoder

package main

import (
	httpsign "github.com/thinkgos/http-signature-go"
)

func main() {
	keystone := httpsign.NewKeystoneMemory()

	httpSignParser := httpsign.NewParser(
		httpsign.WithMinimumRequiredHeaders([]string{
			httpsign.RequestTarget,
			httpsign.Date,
			httpsign.Nonce,
			httpsign.Digest,
		}),
		httpsign.WithSigningMethods(
			httpsign.SigningMethodHmacSha256.Alg(),
			func() httpsign.SigningMethod { return httpsign.SigningMethodHmacSha256 },
		),
		httpsign.WithSigningMethods(
			httpsign.SigningMethodHmacSha384.Alg(),
			func() httpsign.SigningMethod { return httpsign.SigningMethodHmacSha384 },
		),
		httpsign.WithSigningMethods(
			httpsign.SigningMethodHmacSha512.Alg(),
			func() httpsign.SigningMethod { return httpsign.SigningMethodHmacSha512 },
		),
		httpsign.WithValidators(
			httpsign.NewDigestUsingSharedValidator(),
			httpsign.NewDateValidator(),
		),
		httpsign.WithKeystone(keystone),
	)

	err := httpSignParser.AddMetadata(
		httpsign.KeyId("key_id_1"),
		httpsign.Metadata{
			Scheme: httpsign.SchemeSignature,
			Alg:    "hmac-sha512",
			Key:    []byte("key_secret_1"),
		},
	)
	if err != nil {
		panic(err)
	}
	err = httpSignParser.AddMetadata(
		httpsign.KeyId("key_id_2"),
		httpsign.Metadata{
			Scheme: httpsign.SchemeSignature,
			Alg:    "hmac-sha512",
			Key:    []byte("key_secret_2"),
		},
	)
	if err != nil {
		panic(err)
	}

	// parser http.Request
	// httpSignParser.ParseFromRequest() and httpSignParser.Verify
	// or
	// httpSignParser.ParseVerify()
}
