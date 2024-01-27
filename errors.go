package cryptox

import (
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

// NewDecryptionError returns a new DecryptionError error.
func NewDecryptionError(msg string, err error) *DecryptionError {
	return &DecryptionError{
		cryptoError: newCryptoError(DecryptionErrorCode, msg, err),
	}
}

// EncryptionErrror occurs when there's an error encrypting plaintext.
type EncryptionError struct {
	*cryptoError
}

// NewEncryptionError returns a new EncryptionError error.
func NewEncryptionError(msg string, err error) *EncryptionError {
	return &EncryptionError{
		cryptoError: newCryptoError(EncryptionErrorCode, msg, err),
	}
}

// InvalidPublicKeyError occurs when an improperly formatted RSA public key is encountered.
type InvalidPublicKeyError struct {
	*cryptoError
}

// NewInvalidPublicKeyError returns a new InvalidPublicKeyError error.
func NewInvalidPublicKeyError(msg string, err error) *InvalidPublicKeyError {
	return &InvalidPublicKeyError{
		cryptoError: newCryptoError(InvalidPublicKeyErrorCode, msg, err),
	}
}

// SignatureError occurs when there is an error signing content with an RSA private key.
type SignatureError struct {
	*cryptoError
}

// NewSignatureError returns a new SignatureError error.
func NewSignatureError(msg string, err error) *SignatureError {
	return &SignatureError{
		cryptoError: newCryptoError(SignatureErrorCode, msg, err),
	}
}

// LoadCertificateError occurs when there is an error loading one or more certificates.
type LoadCertificateError struct {
	*cryptoError
}

// NewLoadCertificateError returns a new LoadCertificateError error.
func NewLoadCertificateError(msg string, err error) *LoadCertificateError {
	return &LoadCertificateError{
		cryptoError: newCryptoError(LoadCertificateErrorCode, msg, err),
	}
}

// InvalidCertificateError occurs when an improperly formatted X509 certificate is encountered.
type InvalidCertificateError struct {
	*cryptoError
}

// NewInvalidCertificateError returns a new InvalidCertificateError error.
func NewInvalidCertificateError(msg string, err error) *InvalidCertificateError {
	return &InvalidCertificateError{
		cryptoError: newCryptoError(InvalidCertificateErrorCode, msg, err),
	}
}

// RSAPrivateKeyError occurs when there is an error with an RSA private key.
type RSAPrivateKeyError struct {
	*cryptoError
}

// NewRSAPrivateKeyError returns a new RSAPrivateKeyError error.
func NewRSAPrivateKeyError(msg string, err error) *RSAPrivateKeyError {
	return &RSAPrivateKeyError{
		cryptoError: newCryptoError(RSAPrivateKeyErrorCode, msg, err),
	}
}

// X509CertificateError occurs when there is an error with an X509 certificate.
type X509CertificateError struct {
	*cryptoError
}

// NewX509CertificateError returns a new X509CertificateError error.
func NewX509CertificateError(msg string, err error) *X509CertificateError {
	return &X509CertificateError{
		cryptoError: newCryptoError(X509CertificateErrorCode, msg, err),
	}
}

// JWTError occurs when there is an error with a Java Web Token.
type JWTError struct {
	*cryptoError
}

// NewJWTError returns a new JWTError error.
func NewJWTError(msg string, err error) *JWTError {
	return &JWTError{
		cryptoError: newCryptoError(JWTErrorCode, msg, err),
	}
}

// PGPError occurs when there is an error with a PGP operation.
type PGPError struct {
	*cryptoError
}

// NewPGPError returns a new PGPError error.
func NewPGPError(msg string, err error) *PGPError {
	return &PGPError{
		cryptoError: newCryptoError(PGPErrorCode, msg, err),
	}
}

// PEMGeneralError occurs when there is a general error during PEM-related operations.
type PEMGeneralError struct {
	*cryptoError
}

// NewPEMGeneralError returns a new PEMGeneralError error.
func NewPEMGeneralError(msg string, err error) *PEMGeneralError {
	return &PEMGeneralError{
		cryptoError: newCryptoError(PEMGeneralErrorCode, msg, err),
	}
}
