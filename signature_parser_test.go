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

var testSigningMethodSha256 = &SigningMethodHash{"sha256", crypto.SHA256}

// SigningMethodHash implements the HMAC-SHA family of signing methods.
// Expects key type of []byte for both signing and validation
type SigningMethodHash struct {
	Name string
	Hash crypto.Hash
}

func (m *SigningMethodHash) Alg() string { return m.Name }

func (m *SigningMethodHash) Verify(signingString []byte, sig []byte, _ any) error {
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

func (m *SigningMethodHash) Sign(signingString []byte, _ any) ([]byte, error) {
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

func newAuthorizationHeader(s string) http.Header {
	return http.Header{
		HeaderAuthorizationHeader: []string{s},
	}
}

// `(request-target)`, `(created)`, `(expires)`
func newAuthorizationHeader1(s string) http.Header {
	return http.Header{
		HeaderAuthorizationHeader: []string{s},
		RequestTarget:             []string{sampleRequestTarget},
		Created:                   []string{sampleTimestampStr},
		Expires:                   []string{sampleTimestampStr},
	}
}

// `(request-target)`, `(created)`, `(expires)`
// invalid created value
func newAuthorizationHeader1InvalidCreated(s string) http.Header {
	return http.Header{
		HeaderAuthorizationHeader: []string{s},
		RequestTarget:             []string{sampleRequestTarget},
		Created:                   []string{sampleTimestampInvalid},
	}
}

// `(request-target)`, `(created)`, `(expires)`
// invalid expires value
func newAuthorizationHeader1InvalidExpires(s string) http.Header {
	return http.Header{
		HeaderAuthorizationHeader: []string{s},
		RequestTarget:             []string{sampleRequestTarget},
		Created:                   []string{sampleTimestampStr},
		Expires:                   []string{sampleTimestampInvalid},
	}
}

// `(request-target)`, `(date)`
func newAuthorizationHeader2(s string) http.Header {
	return http.Header{
		HeaderAuthorizationHeader: []string{s},
		RequestTarget:             []string{sampleRequestTarget},
		Date:                      []string{sampleDate},
	}
}

func newSignatureHeader(s string) http.Header {
	return http.Header{
		HeaderSignature: []string{s},
		RequestTarget:   []string{sampleRequestTarget},
		Date:            []string{sampleDate},
	}
}

func newTestParser(vs ...Validator) (*Parser, error) {
	parser := NewParser(
		WithExtractor(NewMultiExtractor(
			NewSignatureExtractor(HeaderSignature),
			NewAuthorizationSignatureExtractor(HeaderAuthorizationHeader),
		)),
		WithValidators(vs...),
		WithKeystone(NewKeystoneMemory()),
		WithSigningMethods("hmac-sha256", func() SigningMethod { return SigningMethodHmacSha512 }),
		WithSigningMethods("sha256", func() SigningMethod { return testSigningMethodSha256 }),
	)
	err := parser.AddMetadata("key_id_hs", Metadata{
		Scheme: SchemeUnspecified,
		Alg:    "hmac-sha256",
		Key:    []byte("1234"),
	})
	if err != nil {
		return nil, err
	}
	err = parser.AddMetadata("key_id_s", Metadata{
		Scheme: SchemeUnspecified,
		Alg:    "sha256",
		Key:    []byte("1234"),
	})
	if err != nil {
		return nil, err
	}
	err = parser.AddMetadata("key_id_s512", Metadata{
		Scheme: SchemeUnspecified,
		Alg:    "sha512",
		Key:    []byte("1234"),
	})
	if err != nil {
		return nil, err
	}
	err = parser.AddMetadata("key_id_scheme", Metadata{
		Scheme: SchemeSignature,
		Alg:    "sha256",
		Key:    []byte("1234"),
	})
	if err != nil {
		return nil, err
	}
	return parser, nil
}

func TestParser(t *testing.T) {
	t.Run("algorithms", func(t *testing.T) {
		parser, err := newTestParser()
		require.NoError(t, err)
		algs := parser.GetSigningMethodAlgorithms()
		sort.Strings(algs)
		require.Equal(t, algs, []string{"hmac-sha256", "sha256"})
	})
	t.Run("metadata", func(t *testing.T) {
		parser, err := newTestParser()
		require.NoError(t, err)

		_, err = parser.GetMetadata("key_id_s")
		require.NoError(t, err)
		err = parser.DeleteMetadata("key_id_s")
		require.NoError(t, err)
		_, err = parser.GetMetadata("key_id_s")
		require.ErrorIs(t, err, ErrKeyIdInvalid)
	})
}

func TestParse_ParserFromRequest(t *testing.T) {
	parser, err := newTestParser()
	require.NoError(t, err)
	tests := []struct {
		name          string
		header        http.Header
		wantParameter *Parameter
		err           error
	}{
		{
			name:          `empty headers`,
			header:        http.Header{},
			wantParameter: nil,
			err:           ErrNoSignatureInRequest,
		},
		{
			name:          `Authorization Signature - invalid begin`,
			header:        newAuthorizationHeader(`notASignature keyId="key_id_hs",algorithm="hmac-sha256",headers="(request-target) date digest",signature="70AaN3BDO0XC9QbtgksgCy2jJvmOvshq8VmjSthdXC+sgcgrKrl9WME4DbZv4W7UZKElvCemhDLHQ1Nln9GMkQ=="`),
			wantParameter: nil,
			err:           ErrNoSignatureInRequest,
		},
		{
			name:          `Authorization Signature - invalid key pair format`,
			header:        newAuthorizationHeader(`Signature xxx`),
			wantParameter: nil,
			err:           ErrMissingEqualCharacter,
		},
		{
			name:          `Authorization Signature - missing keyId`,
			header:        newAuthorizationHeader(`Signature algorithm="hmac-sha256",headers="(request-target) date digest",signature="70AaN3BDO0XC9QbtgksgCy2jJvmOvshq8VmjSthdXC+sgcgrKrl9WME4DbZv4W7UZKElvCemhDLHQ1Nln9GMkQ=="`),
			wantParameter: nil,
			err:           ErrKeyIdMissing,
		},
		{
			name:          `Authorization Signature - missing signature`,
			header:        newAuthorizationHeader(`Signature keyId="key_id_hs",algorithm="hmac-sha256",headers="(request-target) date digest"`),
			wantParameter: nil,
			err:           ErrSignatureMissing,
		},
		{
			name:          `Authorization Signature - (created) parameter invalid`,
			header:        newAuthorizationHeader1(fmt.Sprintf(`Signature keyId="key_id_s",algorithm="sha256",created="%s",headers="",signature="2XTrrRivi/zKazfSd7pTy3Z9w+AkjLlWBIyEb9/crx0LMzTZhnAhEYwe9O3yicB2JJB2eZuW2CHwbBtDJqSMBQ=="`, sampleTimestampInvalid)),
			wantParameter: nil,
			err:           ErrCreatedInvalid,
		},
		{
			name:          `Authorization Signature - (expires) parameter invalid`,
			header:        newAuthorizationHeader1(fmt.Sprintf(`Signature keyId="key_id_s",algorithm="sha256",expires="%s",headers="(request-target) (created) (expires)",signature="2XTrrRivi/zKazfSd7pTy3Z9w+AkjLlWBIyEb9/crx0LMzTZhnAhEYwe9O3yicB2JJB2eZuW2CHwbBtDJqSMBQ=="`, sampleTimestampInvalid)),
			wantParameter: nil,
			err:           ErrExpiresInvalid,
		},
		{
			name:   `Authorization Signature - done`,
			header: newAuthorizationHeader1(`Signature keyId="key_id_s",algorithm="sha256",headers="(request-target) (created) (expires)",signature="Ojk0U+TJp6d29IsWjLBlTIVn/s5X9DS1Tc0xiA9W0TM="`),
			wantParameter: &Parameter{
				KeyId:     "key_id_s",
				Algorithm: "sha256",
				Headers:   []string{"(request-target)", "(created)", "(expires)"},
				Signature: "Ojk0U+TJp6d29IsWjLBlTIVn/s5X9DS1Tc0xiA9W0TM=",
				Scheme:    SchemeAuthentication,
				headerMap: map[string]struct{}{
					"(request-target)": {},
					"(created)":        {},
					"(expires)":        {},
				},
			},
			err: nil,
		},
		{
			name:   `Signature - done`,
			header: newSignatureHeader(`keyId="key_id_hs",algorithm="hmac-sha256",headers="",signature="fM9R84nzuAa1YB7gxiV13etzOU8AuNV1qw+xz0wLtV5Izq6PNziAQYMAy2SHm+Aru3tZGoxNYIGD5g4j2HKQ7Q=="`),
			wantParameter: &Parameter{
				KeyId:     "key_id_hs",
				Algorithm: "hmac-sha256",
				Headers:   []string{"(request-target)", "date"},
				Signature: "fM9R84nzuAa1YB7gxiV13etzOU8AuNV1qw+xz0wLtV5Izq6PNziAQYMAy2SHm+Aru3tZGoxNYIGD5g4j2HKQ7Q==",
				Scheme:    SchemeSignature,
				headerMap: map[string]struct{}{
					"(request-target)": {},
					"date":             {},
				},
			},
			err: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
			require.NoError(t, err, tc.name)
			r.Header = tc.header

			gotParam, err := parser.ParseFromRequest(r)
			require.Equal(t, tc.err, err)
			if err == nil {
				require.Equal(t, tc.wantParameter, gotParam)
			}
		})
	}
}

func TestParser_Verify(t *testing.T) {
	tests := []struct {
		name          string
		header        http.Header
		wantParameter *Parameter
		err           error
	}{
		// {
		// 	name:          `Authorization Signature - parameter headers not meet minimum required`,
		// 	header:        newAuthorizationHeader(`Signature keyId="key_id_hs",algorithm="hmac-sha256",headers="date",signature="2XTrrRivi/zKazfSd7pTy3Z9w+AkjLlWBIyEb9/crx0LMzTZhnAhEYwe9O3yicB2JJB2eZuW2CHwbBtDJqSMBQ=="`),
		// 	wantParameter: nil,
		// 	err:           ErrMinimumRequiredHeader,
		// },
		// {
		// 	name:          `Authorization Signature - keyId not found`,
		// 	header:        newAuthorizationHeader1(`Signature keyId="key_id_xxx",algorithm="sha256",headers="(request-target) (created) (expires)",signature="Ojk0U+TJp6d29IsWjLBlTIVn/s5X9DS1Tc0xiA9W0TM="`),
		// 	wantParameter: nil,
		// 	err:           ErrKeyIdInvalid,
		// },
		// {
		// 	name:          `Authorization Signature - algorithm mismatch`,
		// 	header:        newAuthorizationHeader1(`Signature keyId="key_id_s",algorithm="sha512",headers="(request-target) (created) (expires)",signature="Ojk0U+TJp6d29IsWjLBlTIVn/s5X9DS1Tc0xiA9W0TM="`),
		// 	wantParameter: nil,
		// 	err:           ErrAlgorithmMismatch,
		// },
		// {
		// 	name:          `Authorization Signature - algorithm not register, mismatch`,
		// 	header:        newAuthorizationHeader1(`Signature keyId="key_id_s512",algorithm="sha512",headers="(request-target) (created) (expires)",signature="Ojk0U+TJp6d29IsWjLBlTIVn/s5X9DS1Tc0xiA9W0TM="`),
		// 	wantParameter: nil,
		// 	err:           ErrAlgorithmUnsupported,
		// },
		// {
		// 	name:          `Authorization Signature - signature , base64 decode failure`,
		// 	header:        newAuthorizationHeader1(`Signature keyId="key_id_s",algorithm="sha256",headers="(request-target) (created) (expires)",signature="Ojk0U+TJp6d29IsWjLBlTIVn/s5X9DS1Tc0xiA9W0TM=x"`),
		// 	wantParameter: nil,
		// 	err:           ErrSignatureInvalid,
		// },
		// {
		// 	name:          `Authorization Signature - signature , verify failure`,
		// 	header:        newAuthorizationHeader1(`Signature keyId="key_id_s",algorithm="sha256",headers="(request-target) (created)",signature="Ojk0U+TJp6d29IsWjLBlTIVn/s5X9DS1Tc0xiA9W0TM="`),
		// 	wantParameter: nil,
		// 	err:           ErrSignatureInvalid,
		// },
		// {
		// 	name:          `Authorization Signature - scheme not support`,
		// 	header:        newAuthorizationHeader1(`Signature keyId="key_id_scheme",algorithm="sha256",headers="(request-target) (created) (expires)",signature="Ojk0U+TJp6d29IsWjLBlTIVn/s5X9DS1Tc0xiA9W0TM="`),
		// 	wantParameter: nil,
		// 	err:           ErrSchemeUnsupported,
		// },
		{
			name:   `Authorization Signature - done`,
			header: newAuthorizationHeader1(`Signature keyId="key_id_s",algorithm="sha256",headers="(request-target) (created) (expires)",signature="pRWnJN0SU21wZmwLLeH6ftb84KNceu7SFzVcB3cW+Zc="`),
			wantParameter: &Parameter{
				KeyId:     "key_id_s",
				Algorithm: "sha256",
				Headers:   []string{"(request-target)", "(created)", "(expires)"},
				Signature: "pRWnJN0SU21wZmwLLeH6ftb84KNceu7SFzVcB3cW+Zc=",
				Scheme:    SchemeAuthentication,
				Method:    testSigningMethodSha256,
				Key:       []byte("1234"),
				headerMap: map[string]struct{}{
					"(request-target)": {},
					"(created)":        {},
					"(expires)":        {},
				},
			},
			err: nil,
		},
		// {
		// 	name:   `Signature - done`,
		// 	header: newSignatureHeader(`keyId="key_id_hs",algorithm="hmac-sha256",headers="",signature="fM9R84nzuAa1YB7gxiV13etzOU8AuNV1qw+xz0wLtV5Izq6PNziAQYMAy2SHm+Aru3tZGoxNYIGD5g4j2HKQ7Q=="`),
		// 	wantParameter: &Parameter{
		// 		KeyId:     "key_id_hs",
		// 		Algorithm: "hmac-sha256",
		// 		Headers:   []string{"(request-target)", "date"},
		// 		Signature: "fM9R84nzuAa1YB7gxiV13etzOU8AuNV1qw+xz0wLtV5Izq6PNziAQYMAy2SHm+Aru3tZGoxNYIGD5g4j2HKQ7Q==",
		// 		Scheme:    SchemeSignature,
		// 		Method:    SigningMethodHmacSha512,
		// 		Key:       []byte("1234"),
		// 		headerMap: map[string]struct{}{
		// 			"(request-target)": {},
		// 			"date":             {},
		// 		},
		// 	},
		// 	err: nil,
		// },
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
			require.NoError(t, err, tc.name)
			r.Header = tc.header

			parser, err := newTestParser()
			require.NoError(t, err)
			gotParam, err := parser.ParseFromRequest(r)
			require.NoError(t, err)

			err = parser.Verify(r, gotParam)
			require.Equal(t, tc.err, err)
			if err == nil {
				require.Equal(t, tc.wantParameter, gotParam)
			}
		})
	}
}

func TestParser_ParserVerify(t *testing.T) {
	parser, err := newTestParser()
	require.NoError(t, err)
	tests := []struct {
		name       string
		header     http.Header
		wantScheme Scheme
		err        error
	}{
		{
			name:       `empty headers`,
			header:     http.Header{},
			wantScheme: SchemeUnspecified,
			err:        ErrNoSignatureInRequest,
		},
		{
			name:       `Authorization Signature - parameter headers not meet minimum required`,
			header:     newAuthorizationHeader(`Signature keyId="key_id_hs",algorithm="hmac-sha256",headers="date",signature="2XTrrRivi/zKazfSd7pTy3Z9w+AkjLlWBIyEb9/crx0LMzTZhnAhEYwe9O3yicB2JJB2eZuW2CHwbBtDJqSMBQ=="`),
			wantScheme: SchemeAuthentication,
			err:        ErrMinimumRequiredHeader,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
			require.NoError(t, err, tc.name)
			r.Header = tc.header

			scheme, err := parser.ParseVerify(r)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.wantScheme, scheme)
		})
	}
}
