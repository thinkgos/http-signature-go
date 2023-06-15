package httpsign

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

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

func TestSignature_EncodeDecode(t *testing.T) {
	r, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	require.NoError(t, err)

	p1 := &Parameter{
		KeyId:     "key_id_1",
		Signature: "",
		Algorithm: "",
		Created:   sampleTimestamp,
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

	want := fmt.Sprintf(`keyId="key_id_1",algorithm="hmac-sha256",created=1686625874,headers="(request-target) (created) host",signature="%s"`, p1.Signature) //nolint: lll
	require.Equal(t, want, r.Header.Get(SignatureHeader))
	require.Equal(t, wantCreatedHeader, r.Header.Get(CreatedHeader))

	parser := NewParser(
		WithMinimumRequiredHeaders([]string{RequestTargetHeader, CreatedHeader, HostHeader}),
		WithSigningMethods(SigningMethodHmacSha256.Alg(), func() SigningMethod { return SigningMethodHmacSha256 }),
		WithValidators(&createdAlwaysValid{}),
	)
	err = parser.AddMetadata("key_id_1", Metadata{
		Scheme: SchemeUnspecified,
		Alg:    SigningMethodHmacSha256.Alg(),
		Key:    []byte("1234"),
	})
	require.NoError(t, err)
	gotParam, err := parser.ParseFromRequest(r)
	require.NoError(t, err)
	require.Equal(t, p1.KeyId, gotParam.KeyId)
	require.Equal(t, p1.Signature, gotParam.Signature)
	require.Equal(t, p1.Algorithm, gotParam.Algorithm)
	require.Equal(t, p1.Created, gotParam.Created)
	require.Equal(t, p1.Expires, gotParam.Expires)
	require.Equal(t, p1.Headers, gotParam.Headers)
	require.Equal(t, p1.Scheme, gotParam.Scheme)

	err = parser.Verify(r, gotParam)
	require.NoError(t, err)
	require.Equal(t, p1.Method, gotParam.Method)
	require.Equal(t, p1.Key, gotParam.Key)
}
