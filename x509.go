package cryptox

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"go.innotegrity.dev/errorx"
)

// CertificatePool stores X509 certificates.
type CertificatePool struct {
	*x509.CertPool
}

// NewCertificatePool creates a new CertificatePool object.
//
// If empty is true, return an empty certificate pool instead of a pool containing a copy of all of the system's
// trusted root certificates.
//
// The following errors are returned by this function:
// LoadCertificateError
func NewCertificatePool(ctx context.Context, emptyPool bool) (*CertificatePool, errorx.Error) {
	if emptyPool {
		return &CertificatePool{
			CertPool: x509.NewCertPool(),
		}, nil
	}

	pool, err := getSystemPool()
	if err != nil {
		return nil, NewLoadCertificateErrorWithContext(ctx, "failed to get system certificate pool", err)
	}
	return &CertificatePool{
		CertPool: pool,
	}, nil
}

// AddPEMCertificatesFromFile adds one or more PEM-formatted certificates from a file to the certificate pool.
//
// The following errors are returned by this function:
// LoadCertificateError
func (p *CertificatePool) AddPEMCertificatesFromFile(ctx context.Context, file string) errorx.Error {
	contents, err := os.ReadFile(file)
	if err != nil {
		return NewLoadCertificateErrorWithContext(ctx, fmt.Sprintf("failed to read certificate file '%s'", file), err).
			WithAttr("certificate_file", file)
	}

	if !p.AppendCertsFromPEM([]byte(contents)) {
		return NewLoadCertificateErrorWithContext(ctx, fmt.Sprintf("failed to read certificate file '%s'", file),
			errors.New("one or more PEM certificates werre not parsed")).WithAttr("certificate_file", file)
	}
	return nil
}

// ValidateCertificate verifies the given certificate is completely trusted.
//
// If the certificate was signed with a key that is not trusted by the default system certificate pool, be sure
// to specify a root CA certificate pool and, if necessary, an intermediate pool containing the certificates
// required to verify the chain.
//
// If you wish to match against specific X509 extended key usages such as verifying the signing key has the
// Code Signing key usage, pass those fields in the keyUsages parameter.
//
// If you wish to verify the common name (CN) field of the public key passed in, specify a non-empty string
// for the cn parameter. This match is case-sensitive.
//
// The following errors are returned by this function:
// InvalidCertificateError
func ValidateCertificate(ctx context.Context, cert *x509.Certificate, roots *CertificatePool,
	intermediates *CertificatePool, keyUsages []x509.ExtKeyUsage, cn string) errorx.Error {

	if cert == nil {
		return NewInvalidCertificateErrorWithContext(ctx, "failed to validate certificate",
			errors.New("no certificate was provided"))
	}

	// verify the certificate chain and usage
	verifyOptions := x509.VerifyOptions{}
	if roots != nil {
		verifyOptions.Roots = roots.CertPool
	}
	if intermediates != nil {
		verifyOptions.Intermediates = intermediates.CertPool
	}
	if keyUsages != nil {
		verifyOptions.KeyUsages = keyUsages
	}
	if _, err := cert.Verify(verifyOptions); err != nil {
		return NewInvalidCertificateErrorWithContext(ctx, "failed to validate certificate", err)
	}

	// verify the common name
	if cn != "" && cert.Subject.CommonName != cn {
		return NewInvalidCertificateErrorWithContext(ctx, "failed to validate certificate",
			fmt.Errorf("CommonName '%s' does not match expected CN '%s'", cert.Subject.CommonName, cn))
	}
	return nil
}

// NewSelfSignedCertificateKeyPair creates a new self-signed certificate using the given template and returns the
// public certificate and private key, respectively, on success.
//
// The following errors are returned by this function:
// RSAPrivateKeyError, X509CertificateError
func NewSelfSignedCertificateKeyPair(ctx context.Context, template *x509.Certificate, keyBits int) (
	[]byte, []byte, error) {

	// generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, nil, NewRSAPrivateKeyErrorWithContext(ctx, "failed to generate private key", err)
	}
	publicKey := &privateKey.PublicKey
	key := new(bytes.Buffer)
	if err := pem.Encode(key, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}); err != nil {
		return nil, nil, NewRSAPrivateKeyErrorWithContext(ctx, "failed to encode private key", err)
	}

	// create a self-signed certificate
	var parent = template
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		return nil, nil, NewX509CertificateErrorWithContext(ctx, "failed to create X509 certificate", err)
	}
	cert := new(bytes.Buffer)
	if err := pem.Encode(cert, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		return nil, nil, NewX509CertificateErrorWithContext(ctx, "failed to encode X509 certificate", err)
	}
	return cert.Bytes(), key.Bytes(), nil
}
