package cryptox

import (
	"context"
	"fmt"

	"go.innotegrity.dev/errorx"
)

const (
	// Library error codes
	DecryptionErrorCode         = 5001
	EncryptionErrorCode         = 5002
	InvalidPublicKeyErrorCode   = 5003
	SignatureErrorCode          = 5004
	InvalidSignatureCode        = 5005
	LoadCertificateErrorCode    = 5006
	InvalidCertificateErrorCode = 5007
	RSAPrivateKeyErrorCode      = 5008
	X509CertificateErrorCode    = 5009
	JWTErrorCode                = 5010
	PGPErrorCode                = 5011
	PEMGeneralErrorCode         = 5012
)

// cryptoError is a generic base class for cryptography errors that include a message.
type cryptoError struct {
	*errorx.BaseError

	// unexported fields
	msg string
}

// newCryptoError creates a new cryptoError error.
func newCryptoError(code int, msg string, err error) *cryptoError {
	return &cryptoError{
		BaseError: errorx.NewBaseError(code, err),
		msg:       msg,
	}
}

// newCryptoErrorWithContext creates a new cryptoError error with context.
func newCryptoErrorWithContext(ctx context.Context, code int, msg string, err error) *cryptoError {
	count, _ := errorx.AdjustFramesCountByFromContext(ctx)
	return &cryptoError{
		BaseError: errorx.NewBaseErrorWithContext(errorx.ContextWithAdjustFramesCountBy(ctx, count+1), code, err),
		msg:       msg,
	}
}

// Error returns the string version of the error.
func (e *cryptoError) Error() string {
	if e.InternalError() != nil {
		return fmt.Sprintf("%s: %s", e.msg, e.InternalError().Error())
	}
	return e.msg
}

// Msg returns the associated error message.
func (e *cryptoError) Msg() string {
	return e.msg
}

// DecryptionErrror occurs when there's an error decrypting ciphertext.
type DecryptionError struct {
	*cryptoError
}

// NewDecryptionError creates a new DecryptionError error.
func NewDecryptionError(msg string, err error) *DecryptionError {
	return &DecryptionError{
		cryptoError: newCryptoError(DecryptionErrorCode, msg, err),
	}
}

// NewDecryptionErrorWithContext creates a new DecryptionError error with context.
func NewDecryptionErrorWithContext(ctx context.Context, msg string, err error) *DecryptionError {
	return &DecryptionError{
		cryptoError: newCryptoErrorWithContext(ctx, DecryptionErrorCode, msg, err),
	}
}

// EncryptionErrror occurs when there's an error encrypting plaintext.
type EncryptionError struct {
	*cryptoError
}

// NewEncryptionError creates a new EncryptionError error.
func NewEncryptionError(msg string, err error) *EncryptionError {
	return &EncryptionError{
		cryptoError: newCryptoError(EncryptionErrorCode, msg, err),
	}
}

// NewEncryptionErrorWithContext creates a new EncryptionError error with context.
func NewEncryptionErrorWithContext(ctx context.Context, msg string, err error) *EncryptionError {
	return &EncryptionError{
		cryptoError: newCryptoErrorWithContext(ctx, EncryptionErrorCode, msg, err),
	}
}

// InvalidPublicKeyError occurs when an improperly formatted RSA public key is encountered.
type InvalidPublicKeyError struct {
	*cryptoError
}

// NewInvalidPublicKeyError creates a new InvalidPublicKeyError error.
func NewInvalidPublicKeyError(msg string, err error) *InvalidPublicKeyError {
	return &InvalidPublicKeyError{
		cryptoError: newCryptoError(InvalidPublicKeyErrorCode, msg, err),
	}
}

// NewInvalidPublicKeyErrorWithContext creates a new InvalidPublicKeyError error with context.
func NewInvalidPublicKeyErrorWithContext(ctx context.Context, msg string, err error) *InvalidPublicKeyError {
	return &InvalidPublicKeyError{
		cryptoError: newCryptoErrorWithContext(ctx, InvalidPublicKeyErrorCode, msg, err),
	}
}

// SignatureError occurs when there is an error signing content with an RSA private key.
type SignatureError struct {
	*cryptoError
}

// NewSignatureError creates a new SignatureError error.
func NewSignatureError(msg string, err error) *SignatureError {
	return &SignatureError{
		cryptoError: newCryptoError(SignatureErrorCode, msg, err),
	}
}

// NewSignatureErrorWithContext creates a new SignatureError error with context.
func NewSignatureErrorWithContext(ctx context.Context, msg string, err error) *SignatureError {
	return &SignatureError{
		cryptoError: newCryptoErrorWithContext(ctx, SignatureErrorCode, msg, err),
	}
}

// LoadCertificateError occurs when there is an error loading one or more certificates.
type LoadCertificateError struct {
	*cryptoError
}

// NewLoadCertificateError creates a new LoadCertificateError error.
func NewLoadCertificateError(msg string, err error) *LoadCertificateError {
	return &LoadCertificateError{
		cryptoError: newCryptoError(LoadCertificateErrorCode, msg, err),
	}
}

// NewLoadCertificateErrorWithContext creates a new LoadCertificateError error with context.
func NewLoadCertificateErrorWithContext(ctx context.Context, msg string, err error) *LoadCertificateError {
	return &LoadCertificateError{
		cryptoError: newCryptoErrorWithContext(ctx, LoadCertificateErrorCode, msg, err),
	}
}

// InvalidCertificateError occurs when an improperly formatted X509 certificate is encountered.
type InvalidCertificateError struct {
	*cryptoError
}

// NewInvalidCertificateError creates a new InvalidCertificateError error.
func NewInvalidCertificateError(msg string, err error) *InvalidCertificateError {
	return &InvalidCertificateError{
		cryptoError: newCryptoError(InvalidCertificateErrorCode, msg, err),
	}
}

// NewInvalidCertificateErrorWithContext creates a new InvalidCertificateError error with context.
func NewInvalidCertificateErrorWithContext(ctx context.Context, msg string, err error) *InvalidCertificateError {
	return &InvalidCertificateError{
		cryptoError: newCryptoErrorWithContext(ctx, InvalidCertificateErrorCode, msg, err),
	}
}

// RSAPrivateKeyError occurs when there is an error with an RSA private key.
type RSAPrivateKeyError struct {
	*cryptoError
}

// NewRSAPrivateKeyError creates a new RSAPrivateKeyError error.
func NewRSAPrivateKeyError(msg string, err error) *RSAPrivateKeyError {
	return &RSAPrivateKeyError{
		cryptoError: newCryptoError(RSAPrivateKeyErrorCode, msg, err),
	}
}

// NewRSAPrivateKeyErrorWithContext creates a new RSAPrivateKeyError error with context.
func NewRSAPrivateKeyErrorWithContext(ctx context.Context, msg string, err error) *RSAPrivateKeyError {
	return &RSAPrivateKeyError{
		cryptoError: newCryptoErrorWithContext(ctx, RSAPrivateKeyErrorCode, msg, err),
	}
}

// X509CertificateError occurs when there is an error with an X509 certificate.
type X509CertificateError struct {
	*cryptoError
}

// NewX509CertificateError creates a new X509CertificateError error.
func NewX509CertificateError(msg string, err error) *X509CertificateError {
	return &X509CertificateError{
		cryptoError: newCryptoError(X509CertificateErrorCode, msg, err),
	}
}

// NewX509CertificateErrorWithContext creates a new X509CertificateError error with context.
func NewX509CertificateErrorWithContext(ctx context.Context, msg string, err error) *X509CertificateError {
	return &X509CertificateError{
		cryptoError: newCryptoErrorWithContext(ctx, X509CertificateErrorCode, msg, err),
	}
}

// JWTError occurs when there is an error with a Java Web Token.
type JWTError struct {
	*cryptoError
}

// NewJWTError creates a new JWTError error.
func NewJWTError(msg string, err error) *JWTError {
	return &JWTError{
		cryptoError: newCryptoError(JWTErrorCode, msg, err),
	}
}

// NewJWTErrorWithContext creates a new JWTError error with context.
func NewJWTErrorWithContext(ctx context.Context, msg string, err error) *JWTError {
	return &JWTError{
		cryptoError: newCryptoErrorWithContext(ctx, JWTErrorCode, msg, err),
	}
}

// PGPError occurs when there is an error with a PGP operation.
type PGPError struct {
	*cryptoError
}

// NewPGPError creates a new PGPError error.
func NewPGPError(msg string, err error) *PGPError {
	return &PGPError{
		cryptoError: newCryptoError(PGPErrorCode, msg, err),
	}
}

// NewPGPErrorWithContext creates a new PGPError error with context.
func NewPGPErrorWithContext(ctx context.Context, msg string, err error) *PGPError {
	return &PGPError{
		cryptoError: newCryptoErrorWithContext(ctx, PGPErrorCode, msg, err),
	}
}

// PEMGeneralError occurs when there is a general error during PEM-related operations.
type PEMGeneralError struct {
	*cryptoError
}

// NewPEMGeneralError creates a new PEMGeneralError error.
func NewPEMGeneralError(msg string, err error) *PEMGeneralError {
	return &PEMGeneralError{
		cryptoError: newCryptoError(PEMGeneralErrorCode, msg, err),
	}
}

// NewPEMGeneralErrorWithContext creates a new PEMGeneralError error with context.
func NewPEMGeneralErrorWithContext(ctx context.Context, msg string, err error) *PEMGeneralError {
	return &PEMGeneralError{
		cryptoError: newCryptoErrorWithContext(ctx, PEMGeneralErrorCode, msg, err),
	}
}
