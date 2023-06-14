package httpsign

import (
	"context"
	"crypto"
	"crypto/hmac"
	"fmt"
	"net/http"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

/*************************  sha256 signing method for testing *****************/

var signingMethodSha256 = &SigningMethodHash{"sha256", crypto.SHA256}

// SigningMethodHash implements the HMAC-SHA family of signing methods.
// Expects key type of []byte for both signing and validation
type SigningMethodHash struct {
	Name string
	Hash crypto.Hash
}

func (m *SigningMethodHash) Alg() string { return m.Name }

func (m *SigningMethodHash) Verify(signingString string, sig []byte, _ any) error {
	if !m.Hash.Available() {
		return ErrHashUnavailable
	}
	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))
	if !hmac.Equal(sig, hasher.Sum(nil)) {
		return ErrSignatureInvalid
	}
	return nil
}

func (m *SigningMethodHash) Sign(signingString string, _ any) ([]byte, error) {
	if !m.Hash.Available() {
		return nil, ErrHashUnavailable
	}
	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))
	return hasher.Sum(nil), nil
}

/*************************  sha256 signing method for testing *****************/

const (
	sampleBodyContent      = "hello world"
	sampleRequestTarget    = "get /"
	sampleDate             = "Mon, 12 Jun 2023 01:47:49 GMT"
	sampleTimestamp        = 1686625874
	sampleTimestampStr     = "1686625874"
	sampleTimestampInvalid = "aa"
)

// mock interface always return true
type dateAlwaysValid struct{}

func (v *dateAlwaysValid) Validate(r *http.Request, _ *Parameter) error { return nil }

// mock interface always return true
type timestampAlwaysValid struct{}

func (v *timestampAlwaysValid) ValidateTimestamp(t int64) error { return nil }

type mockParameterValid struct {
	wantParameter *Parameter
	t             *testing.T
}

func (v *mockParameterValid) Validate(r *http.Request, got *Parameter) error {
	require.Equal(v.t, v.wantParameter.KeyId, got.KeyId)
	require.Equal(v.t, v.wantParameter.Signature, got.Signature)
	require.Equal(v.t, v.wantParameter.Algorithm, got.Algorithm)
	require.Equal(v.t, v.wantParameter.Created, got.Created)
	require.Equal(v.t, v.wantParameter.Expires, got.Expires)
	require.Equal(v.t, v.wantParameter.Headers, got.Headers)
	require.Equal(v.t, v.wantParameter.Scheme, got.Scheme)
	return nil
}

var mockValidator = []Validator{
	&dateAlwaysValid{},
	NewDigestValidator(),
}

func newAuthorizationHeader(s string) http.Header {
	return http.Header{
		AuthorizationHeader: []string{s},
	}
}

// `(request-target)`, `(created)`, `(expires)`
func newAuthorizationHeader1(s string) http.Header {
	return http.Header{
		AuthorizationHeader: []string{s},
		RequestTargetHeader: []string{sampleRequestTarget},
		CreatedHeader:       []string{sampleTimestampStr},
		ExpiresHeader:       []string{sampleTimestampStr},
	}
}

// `(request-target)`, `(created)`, `(expires)`
// invalid created value
func newAuthorizationHeader1InvalidCreated(s string) http.Header {
	return http.Header{
		AuthorizationHeader: []string{s},
		RequestTargetHeader: []string{sampleRequestTarget},
		CreatedHeader:       []string{sampleTimestampInvalid},
	}
}

// `(request-target)`, `(created)`, `(expires)`
// invalid expires value
func newAuthorizationHeader1InvalidExpires(s string) http.Header {
	return http.Header{
		AuthorizationHeader: []string{s},
		RequestTargetHeader: []string{sampleRequestTarget},
		CreatedHeader:       []string{sampleTimestampStr},
		ExpiresHeader:       []string{sampleTimestampInvalid},
	}
}

// `(request-target)`, `(date)`
func newAuthorizationHeader2(s string) http.Header {
	return http.Header{
		AuthorizationHeader: []string{s},
		RequestTargetHeader: []string{sampleRequestTarget},
		DateHeader:          []string{sampleDate},
	}
}

func newSignatureHeader(s string) http.Header {
	return http.Header{
		SignatureHeader:     []string{s},
		RequestTargetHeader: []string{sampleRequestTarget},
		DateHeader:          []string{sampleDate},
	}
}

func TestFromSignatureString(t *testing.T) {
	newParserFunc := func(v ...Validator) *Parser {
		parser := NewParser(
			WithValidatorCreated(&timestampAlwaysValid{}),
			WithValidatorExpires(&timestampAlwaysValid{}),
			WithValidators(append(mockValidator, v...)...),
			WithExtractor(NewMultiExtractor(
				NewSignatureExtractor(SignatureHeader),
				NewAuthorizationSignatureExtractor(AuthorizationHeader),
			)),
			WithKeystone(NewKeystoneMemory()),
			WithSigningMethods("hmac-sha256", func() SigningMethod { return SigningMethodHmacSha512 }),
			WithSigningMethods("sha256", func() SigningMethod { return signingMethodSha256 }),
		)
		err := parser.AddMetadata("key_id_hs", Metadata{
			Scheme: SchemeUnspecified,
			Alg:    "hmac-sha256",
			Key:    []byte("1234"),
		})
		require.NoError(t, err)
		err = parser.AddMetadata("key_id_s", Metadata{
			Scheme: SchemeUnspecified,
			Alg:    "sha256",
			Key:    []byte("1234"),
		})
		require.NoError(t, err)
		err = parser.AddMetadata("key_id_s512", Metadata{
			Scheme: SchemeUnspecified,
			Alg:    "sha512",
			Key:    []byte("1234"),
		})
		require.NoError(t, err)
		err = parser.AddMetadata("key_id_scheme", Metadata{
			Scheme: SchemeSignature,
			Alg:    "sha256",
			Key:    []byte("1234"),
		})
		require.NoError(t, err)
		return parser
	}

	t.Run("algorithms", func(t *testing.T) {
		parser := newParserFunc()
		algs := parser.GetSigningMethodAlgorithms()
		sort.Strings(algs)
		require.Equal(t, algs, []string{"hmac-sha256", "sha256"})
	})

	t.Run("metadata", func(t *testing.T) {
		parser := newParserFunc()

		_, err := parser.GetMetadata("key_id_s")
		require.NoError(t, err)
		err = parser.DeleteMetadata("key_id_s")
		require.NoError(t, err)
		_, err = parser.GetMetadata("key_id_s")
		require.ErrorIs(t, err, ErrKeyIdInvalid)
	})

	t.Run("parser", func(t *testing.T) {
		tests := []struct {
			name      string
			header    http.Header
			keyId     string
			algorithm string
			headers   []string
			signature string
			err       error
		}{
			{
				name:   `empty headers`,
				header: http.Header{},
				err:    ErrNoSignatureInRequest,
			},
			{
				name:   `Authorization Signature - invalid begin`,
				header: newAuthorizationHeader(`notASignature keyId="key_id_hs",algorithm="hmac-sha256",headers="(request-target) date digest",signature="70AaN3BDO0XC9QbtgksgCy2jJvmOvshq8VmjSthdXC+sgcgrKrl9WME4DbZv4W7UZKElvCemhDLHQ1Nln9GMkQ=="`),
				err:    ErrNoSignatureInRequest,
			},
			{
				name:   `Authorization Signature - invalid key pair format`,
				header: newAuthorizationHeader(`Signature xxx`),
				err:    ErrMissingEqualCharacter,
			},
			{
				name:   `Authorization Signature - missing keyId`,
				header: newAuthorizationHeader(`Signature algorithm="hmac-sha256",headers="(request-target) date digest",signature="70AaN3BDO0XC9QbtgksgCy2jJvmOvshq8VmjSthdXC+sgcgrKrl9WME4DbZv4W7UZKElvCemhDLHQ1Nln9GMkQ=="`),
				err:    ErrKeyIdMissing,
			},
			{
				name:   `Authorization Signature - missing signature`,
				header: newAuthorizationHeader(`Signature keyId="key_id_hs",algorithm="hmac-sha256",headers="(request-target) date digest"`),
				err:    ErrSignatureMissing,
			},
			{
				name:   `Authorization Signature - parameter headers not meet minimum required`,
				header: newAuthorizationHeader(`Signature keyId="key_id_hs",algorithm="hmac-sha256",headers="date",signature="2XTrrRivi/zKazfSd7pTy3Z9w+AkjLlWBIyEb9/crx0LMzTZhnAhEYwe9O3yicB2JJB2eZuW2CHwbBtDJqSMBQ=="`),
				err:    ErrMinimumRequiredHeader,
			},
			{
				name:   `Authorization Signature - (created) header invalid`,
				header: newAuthorizationHeader1InvalidCreated(`Signature keyId="key_id_s",algorithm="sha256",headers="",signature="2XTrrRivi/zKazfSd7pTy3Z9w+AkjLlWBIyEb9/crx0LMzTZhnAhEYwe9O3yicB2JJB2eZuW2CHwbBtDJqSMBQ=="`),
				err:    ErrCreatedInvalid,
			},
			{
				name:   `Authorization Signature - (created) parameter invalid`,
				header: newAuthorizationHeader1(fmt.Sprintf(`Signature keyId="key_id_s",algorithm="sha256",created="%s",headers="",signature="2XTrrRivi/zKazfSd7pTy3Z9w+AkjLlWBIyEb9/crx0LMzTZhnAhEYwe9O3yicB2JJB2eZuW2CHwbBtDJqSMBQ=="`, sampleTimestampInvalid)),
				err:    ErrCreatedInvalid,
			},
			{
				name:   `Authorization Signature - (created) parameter and headers mismatch`,
				header: newAuthorizationHeader1(fmt.Sprintf(`Signature keyId="key_id_s",algorithm="sha256",created=%d,headers="",signature="2XTrrRivi/zKazfSd7pTy3Z9w+AkjLlWBIyEb9/crx0LMzTZhnAhEYwe9O3yicB2JJB2eZuW2CHwbBtDJqSMBQ=="`, sampleTimestamp+1)),
				err:    ErrCreatedMismatch,
			},
			{
				name:   `Authorization Signature - (expires) header invalid`,
				header: newAuthorizationHeader1InvalidExpires(`Signature keyId="key_id_s",algorithm="sha256",headers="(request-target) (created) (expires)",signature="2XTrrRivi/zKazfSd7pTy3Z9w+AkjLlWBIyEb9/crx0LMzTZhnAhEYwe9O3yicB2JJB2eZuW2CHwbBtDJqSMBQ=="`),
				err:    ErrExpiresInvalid,
			},
			{
				name:   `Authorization Signature - (expires) parameter invalid`,
				header: newAuthorizationHeader1(fmt.Sprintf(`Signature keyId="key_id_s",algorithm="sha256",expires="%s",headers="(request-target) (created) (expires)",signature="2XTrrRivi/zKazfSd7pTy3Z9w+AkjLlWBIyEb9/crx0LMzTZhnAhEYwe9O3yicB2JJB2eZuW2CHwbBtDJqSMBQ=="`, sampleTimestampInvalid)),
				err:    ErrExpiresInvalid,
			},
			{
				name:   `Authorization Signature - (expires) parameter and headers mismatch`,
				header: newAuthorizationHeader1(fmt.Sprintf(`Signature keyId="key_id_s",algorithm="sha256",expires=%d,headers="(request-target) (created) (expires)",signature="2XTrrRivi/zKazfSd7pTy3Z9w+AkjLlWBIyEb9/crx0LMzTZhnAhEYwe9O3yicB2JJB2eZuW2CHwbBtDJqSMBQ=="`, sampleTimestamp+1)),
				err:    ErrExpiresMismatch,
			},
			{
				name:   `Authorization Signature - keyId not found`,
				header: newAuthorizationHeader1(`Signature keyId="key_id_xxx",algorithm="sha256",headers="(request-target) (created) (expires)",signature="Ojk0U+TJp6d29IsWjLBlTIVn/s5X9DS1Tc0xiA9W0TM="`),
				err:    ErrKeyIdInvalid,
			},
			{
				name:   `Authorization Signature - algorithm mismatch`,
				header: newAuthorizationHeader1(`Signature keyId="key_id_s",algorithm="sha512",headers="(request-target) (created) (expires)",signature="Ojk0U+TJp6d29IsWjLBlTIVn/s5X9DS1Tc0xiA9W0TM="`),
				err:    ErrAlgorithmMismatch,
			},
			{
				name:   `Authorization Signature - algorithm not register, mismatch`,
				header: newAuthorizationHeader1(`Signature keyId="key_id_s512",algorithm="sha512",headers="(request-target) (created) (expires)",signature="Ojk0U+TJp6d29IsWjLBlTIVn/s5X9DS1Tc0xiA9W0TM="`),
				err:    ErrAlgorithmUnsupported,
			},
			{
				name:   `Authorization Signature - signature , base64 decode failure`,
				header: newAuthorizationHeader1(`Signature keyId="key_id_s",algorithm="sha256",headers="(request-target) (created) (expires)",signature="Ojk0U+TJp6d29IsWjLBlTIVn/s5X9DS1Tc0xiA9W0TM=x"`),
				err:    ErrSignatureInvalid,
			},
			{
				name:   `Authorization Signature - signature , verify failure`,
				header: newAuthorizationHeader1(`Signature keyId="key_id_s",algorithm="sha256",headers="(request-target) (created)",signature="Ojk0U+TJp6d29IsWjLBlTIVn/s5X9DS1Tc0xiA9W0TM="`),
				err:    ErrSignatureInvalid,
			},
			{
				name:   `Authorization Signature - scheme not support`,
				header: newAuthorizationHeader1(`Signature keyId="key_id_scheme",algorithm="sha256",headers="(request-target) (created) (expires)",signature="Ojk0U+TJp6d29IsWjLBlTIVn/s5X9DS1Tc0xiA9W0TM="`),
				err:    ErrSchemeUnsupported,
			},
			{
				name:      `Authorization Signature - done`,
				header:    newAuthorizationHeader1(`Signature keyId="key_id_s",algorithm="sha256",headers="(request-target) (created) (expires)",signature="Ojk0U+TJp6d29IsWjLBlTIVn/s5X9DS1Tc0xiA9W0TM="`),
				keyId:     "key_id_s",
				algorithm: "sha256",
				headers:   []string{"(request-target)", "(created)", "(expires)"},
				signature: "Ojk0U+TJp6d29IsWjLBlTIVn/s5X9DS1Tc0xiA9W0TM=",
				err:       nil,
			},
			{
				name:      `Signature - done`,
				header:    newSignatureHeader(`keyId="key_id_hs",algorithm="hmac-sha256",headers="",signature="fM9R84nzuAa1YB7gxiV13etzOU8AuNV1qw+xz0wLtV5Izq6PNziAQYMAy2SHm+Aru3tZGoxNYIGD5g4j2HKQ7Q=="`),
				keyId:     "key_id_hs",
				algorithm: "hmac-sha256",
				headers:   []string{"(request-target)", "date"},
				signature: "fM9R84nzuAa1YB7gxiV13etzOU8AuNV1qw+xz0wLtV5Izq6PNziAQYMAy2SHm+Aru3tZGoxNYIGD5g4j2HKQ7Q==",
				err:       nil,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				r, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
				require.NoError(t, err, tc.name)
				r.Header = tc.header
				mpv := &mockParameterFixField{
					wantParameter: &Parameter{
						KeyId:     KeyId(tc.keyId),
						Signature: tc.signature,
						Algorithm: tc.algorithm,
						Headers:   tc.headers,
					},
					t: t,
				}
				_, err = newParserFunc(mpv).Parse(r)
				require.Equal(t, tc.err, err)
				if err != nil {
					return
				}
			})
		}
	})
}

type mockParameterFixField struct {
	wantParameter *Parameter
	t             *testing.T
}

func (v *mockParameterFixField) Validate(r *http.Request, got *Parameter) error {
	require.Equal(v.t, v.wantParameter.KeyId, got.KeyId)
	require.Equal(v.t, v.wantParameter.Signature, got.Signature)
	require.Equal(v.t, v.wantParameter.Algorithm, got.Algorithm)
	require.Equal(v.t, v.wantParameter.Headers, got.Headers)
	return nil
}
