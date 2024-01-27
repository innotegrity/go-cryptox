package cryptox

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"go.innotegrity.dev/errorx"
	"go.innotegrity.dev/slogx"
)

// ParsePublicKeyFromCertificate parses the RSA public key portion from an X509 certificate.
//
// The following errors are returned by this function:
// InvalidPublicKeyError
func ParsePublicKeyFromCertificate(ctx context.Context, cert *x509.Certificate) (*rsa.PublicKey, errorx.Error) {
	logger := slogx.ActiveLoggerFromContext(ctx)
	errAttr := slogx.ErrorAttrNameFromContext(ctx)

	// validate parameters
	if cert == nil {
		e := NewInvalidPublicKeyError("failed to parse public key", errors.New("no certificate was provided"))
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return nil, e
	}

	// extract the RSA public key from the certificate
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		e := NewInvalidPublicKeyError("failed to parse public key",
			errors.New("public key does not appear to be in RSA format"))
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return nil, e
	}
	return publicKey, nil
}

// Sign takes the content and generates a signature using a private key certificate.
//
// Use the DecodePEMData() function to convert a PEM-formatted certificate into a PEM block. If the
// private key is encrypted, use the DecryptPEMBlock() function to decrypt it first.
//
// Use the Verify() function to verify the signature produced for the content.
//
// The following errors are returned by this function:
// InvalidPublicKeyError
func Sign(ctx context.Context, contents []byte, privateKey *rsa.PrivateKey) ([]byte, errorx.Error) {
	logger := slogx.ActiveLoggerFromContext(ctx)
	errAttr := slogx.ErrorAttrNameFromContext(ctx)

	// validate parameters
	if contents == nil {
		e := NewInvalidPublicKeyError("failed to sign contents", errors.New("no content was provided"))
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return nil, e
	}
	if privateKey == nil {
		e := NewInvalidPublicKeyError("failed to sign contents", errors.New("no private key was provided"))
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return nil, e
	}

	// hash the contents so we can sign that
	hash := sha256.New()
	hash.Write(contents) // never returns an error
	hashSum := hash.Sum(nil)

	// use PSS to sign the contents as it is newer and supposedly better than PKCSv1.5
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashSum, nil)
	if err != nil {
		e := NewInvalidPublicKeyError("failed to sign contents", err)
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return nil, e
	}
	return signature, nil
}

// Verify validates that the given contents have not been altered by checking them against the signature and
// public key provided.
//
// Use the Sign() function to create the signature used by this function to ensure the same hashing algorithm
// is applied.
//
// The following errors are returned by this function:
// SignatureError
func Verify(ctx context.Context, contents, signature []byte, publicKey *rsa.PublicKey) errorx.Error {
	logger := slogx.ActiveLoggerFromContext(ctx)
	errAttr := slogx.ErrorAttrNameFromContext(ctx)

	// validate parameters
	if contents == nil {
		e := NewSignatureError("failed to verify signature", errors.New("no content was provided"))
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return e
	}
	if signature == nil {
		e := NewSignatureError("failed to verify signature", errors.New("no signature was provided"))
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return e
	}
	if publicKey == nil {
		e := NewSignatureError("failed to verify signature", errors.New("no public key was provided"))
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return e
	}

	// hash the contents so we can verify that
	hash := sha256.New()
	hash.Write(contents) // never returns an error
	hashSum := hash.Sum(nil)

	// verify the signature
	if err := rsa.VerifyPSS(publicKey, crypto.SHA256, hashSum, signature, nil); err != nil {
		e := NewSignatureError("failed to verify signature", err)
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return e
	}
	return nil
}
