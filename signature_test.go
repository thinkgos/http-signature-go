package httpsign

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mock interface always return true
type timeAlwaysValid struct{}

func (v *timeAlwaysValid) Validate(r *http.Request, _ *Parameter) error { return nil }

func TestSignatureParameter(t *testing.T) {
	r, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	require.NoError(t, err)

	p := &Parameter{
		KeyId:     "key_id_1",
		Signature: "",
		Algorithm: "",
		Created:   sampleTimestamp,
		Expires:   0,
		Headers:   []string{RequestTargetHeader, CreatedHeader},
		Scheme:    SchemeSignature,
		Method:    SigningMethodHmacSha256,
		Key:       []byte("1234"),
	}
	wantCreatedHeader := strconv.FormatInt(p.Created, 10)
	r.Header.Set(CreatedHeader, wantCreatedHeader)
	err = p.MergerHeader(r)
	require.NoError(t, err)
	require.Equal(t, p.Algorithm, p.Method.Alg())

	want := fmt.Sprintf(`keyId="key_id_1",algorithm="hmac-sha256",created=1686625874,headers="(request-target) (created)",signature="%s"`, p.Signature) //nolint: lll
	require.Equal(t, want, r.Header.Get(SignatureHeader))
	require.Equal(t, wantCreatedHeader, r.Header.Get(CreatedHeader))
}

func TestSignature_EncodeDecode_WithValidatorCreated(t *testing.T) {
	r, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	require.NoError(t, err)

	p1 := &Parameter{
		KeyId:     "key_id_1",
		Signature: "",
		Algorithm: "",
		Created:   time.Now().Add(-time.Hour).UTC().Unix(),
		Expires:   0,
		Headers:   []string{RequestTargetHeader, CreatedHeader, HostHeader},
		Scheme:    SchemeSignature,
		Method:    SigningMethodHmacSha256,
		Key:       []byte("1234"),
	}
	wantCreatedHeader := strconv.FormatInt(p1.Created, 10)
	r.Header.Set(CreatedHeader, wantCreatedHeader)
	err = p1.MergerHeader(r)
	require.NoError(t, err)
	require.Equal(t, p1.Algorithm, p1.Method.Alg())

	want := fmt.Sprintf(`keyId="key_id_1",algorithm="hmac-sha256",created=%d,headers="(request-target) (created) host",signature="%s"`, p1.Created, p1.Signature) //nolint: lll
	require.Equal(t, want, r.Header.Get(SignatureHeader))
	require.Equal(t, wantCreatedHeader, r.Header.Get(CreatedHeader))

	// validate created always valid
	parser1 := NewParser(
		WithMinimumRequiredHeaders([]string{RequestTargetHeader, CreatedHeader, HostHeader}),
		WithSigningMethods(SigningMethodHmacSha256.Alg(), func() SigningMethod { return SigningMethodHmacSha256 }),
		WithValidators(&timeAlwaysValid{}),
	)
	err = parser1.AddMetadata("key_id_1", Metadata{
		Scheme: SchemeUnspecified,
		Alg:    SigningMethodHmacSha256.Alg(),
		Key:    []byte("1234"),
	})
	require.NoError(t, err)
	gotParam, err := parser1.ParseFromRequest(r)
	require.NoError(t, err)
	require.Equal(t, p1.KeyId, gotParam.KeyId)
	require.Equal(t, p1.Signature, gotParam.Signature)
	require.Equal(t, p1.Algorithm, gotParam.Algorithm)
	require.Equal(t, p1.Created, gotParam.Created)
	require.Equal(t, p1.Expires, gotParam.Expires)
	require.Equal(t, p1.Headers, gotParam.Headers)
	require.Equal(t, p1.Scheme, gotParam.Scheme)

	err = parser1.Verify(r, gotParam)
	require.NoError(t, err)
	require.Equal(t, p1.Method, gotParam.Method)
	require.Equal(t, p1.Key, gotParam.Key)

	// validate created invalid.

	parser2 := NewParser(
		WithMinimumRequiredHeaders([]string{RequestTargetHeader, CreatedHeader, HostHeader}),
		WithSigningMethods(SigningMethodHmacSha256.Alg(), func() SigningMethod { return SigningMethodHmacSha256 }),
		WithValidators(NewCreatedValidator()),
	)
	err = parser2.AddMetadata("key_id_1", Metadata{
		Scheme: SchemeUnspecified,
		Alg:    SigningMethodHmacSha256.Alg(),
		Key:    []byte("1234"),
	})
	require.NoError(t, err)
	_, err = parser2.ParseVerify(r)
	require.Equal(t, err, ErrCreatedNotInRange)
}
