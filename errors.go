package httpsign

import (
	"errors"
)

var (
	// ErrSchemeUnsupported scheme not supported with keyId.
	ErrSchemeUnsupported = errors.New("scheme unsupported")
	// ErrNoSignatureInRequest `Signature` not found in request.
	ErrNoSignatureInRequest = errors.New("signature not found in request")
	// ErrKeyIdMissing keyId not in header value.
	ErrKeyIdMissing = errors.New("keyId must be in header value")
	// ErrSignatureMissing signature not in header value.
	ErrSignatureMissing = errors.New("signature must be in header value")
	// ErrKeyIdInvalid KeyID in header does not provided.
	ErrKeyIdInvalid = errors.New("keyId invalid")
	// ErrAlgorithmMismatch Algorithm in header does not match with keyId.
	ErrAlgorithmMismatch = errors.New("algorithm does not match")
	// ErrAlgorithmUnsupported Algorithm not supported.
	ErrAlgorithmUnsupported = errors.New("algorithm unsupported")
	// ErrMinimumRequiredHeader minimum requirement header do not meet.
	ErrMinimumRequiredHeader = errors.New("header field is not meet minimum requirement")
	// ErrDateInvalid invalid 'date' in header.
	ErrDateInvalid = errors.New("date invalid in header")
	// ErrDateNotInRange 'date' not in acceptable range.
	ErrDateNotInRange = errors.New("date is not in acceptable range")
	// ErrCreatedInvalid (created) invalid.
	ErrCreatedInvalid = errors.New("(created) invalid")
	// ErrCreatedNotInRange '(created)' not in acceptable range.
	ErrCreatedNotInRange = errors.New("(created) is not in acceptable range")
	// ErrExpiresInvalid (expires) invalid.
	ErrExpiresInvalid = errors.New("(expires) invalid")
	// ErrSignatureExpired '(expires)' has expired in header
	ErrSignatureExpired = errors.New("signature has be expired")
	// ErrSignatureInvalid signing string do not match
	ErrSignatureInvalid = errors.New("signature invalid")
	// ErrDigestMismatch body do not match with submitted digest
	ErrDigestMismatch = errors.New("body is not match with digest")

	// ErrKeyInvalid key is invalid.
	ErrKeyInvalid = errors.New("key is invalid")
	// ErrKeyTypeInvalid key is invalid type
	ErrKeyTypeInvalid = errors.New("key is invalid type")
	// ErrHashUnavailable the requested hash function is unavailable
	ErrHashUnavailable = errors.New("the requested hash function is unavailable")

	// ErrUnterminatedParameter could not parse value
	ErrUnterminatedParameter = errors.New("Unterminated parameter")
	// ErrMissingDoubleQuote after character = not have double quote
	ErrMissingDoubleQuote = errors.New(`Missing " after = character`)
	// ErrMissingEqualCharacter there is no character = before " or , character
	ErrMissingEqualCharacter = errors.New(`Missing = character =`)
)
