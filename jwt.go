package cryptox

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"go.innotegrity.dev/errorx"
)

// JWTAuthService represents any object that is able to generate new JWT tokens and also validate them.
type JWTAuthService interface {
	// GenerateToken should generate a new JWT token with the given claims and return the encoded JWT token.
	GenerateToken(context.Context, jwt.Claims) (string, errorx.Error)

	// VerifyToken should parse and verify the token string and return the resulting JWT token for further validation.
	VerifyToken(context.Context, string) (*jwt.Token, errorx.Error)
}

// JWTAuthHMACService creates and validates JWT tokens that are signed with an HMAC256-hashed secret.
type JWTAuthHMACService struct {
	secret []byte
}

// NewJWTAuthHMACService creates an initializes a new service object.
func NewJWTAuthHMACService(secret []byte) *JWTAuthHMACService {
	return &JWTAuthHMACService{secret: secret}
}

// GenerateToken generates a new JWT token with the given claims.
//
// The following errors are returned by this function:
// JWTError
func (j *JWTAuthHMACService) GenerateToken(ctx context.Context, claims jwt.Claims) (string, errorx.Error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(j.secret)
	if err != nil {
		return "", NewJWTErrorWithContext(ctx, "failed to create new JWT with claims", err)
	}
	return signedToken, nil
}

// VerifyToken parses and verifies the token string, returning the resulting JWT token for further validation.
//
// The service must use the same secret that was used to generate the token being verified.
//
// The following errors are returned by this function:
// JWTError
func (j *JWTAuthHMACService) VerifyToken(ctx context.Context, encodedToken string) (*jwt.Token, errorx.Error) {
	// parse the JWT token
	token, err := jwt.Parse(encodedToken, func(token *jwt.Token) (interface{}, error) {
		method, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok || strings.ToUpper(method.Alg()) != "HS256" {
			e := NewJWTErrorWithContext(ctx, "failed to validate JWT algorithm",
				fmt.Errorf("JWT algorithm '%s' does not match expected 'HS256' algorithm", token.Header["alg"])).
				WithAttr("jwt_alg", token.Header["alg"])
			return nil, e
		}
		return j.secret, nil
	})
	if err != nil {
		return nil, NewJWTErrorWithContext(ctx, "failed to parse JWT", err)
	}
	return token, nil
}

// JWTAuthRSAService creates and validates JWT tokens that are signed with a private RSA key and validated with a
// public RSA key.
type JWTAuthRSAService struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

// NewJWTAuthRSAService creates an initializes a new service object.
func NewJWTAuthRSAService(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) *JWTAuthRSAService {
	return &JWTAuthRSAService{
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

// GenerateToken generates a new JWT token with the given claims.
//
// The following errors are returned by this function:
// JWTError
func (j *JWTAuthRSAService) GenerateToken(ctx context.Context, claims jwt.Claims) (string, errorx.Error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(j.privateKey)
	if err != nil {
		return "", NewJWTErrorWithContext(ctx, "failed to generate JWT", err)
	}
	return signedToken, nil
}

// VerifyToken parses and verifies the token string, returning the resulting JWT token for further validation.
//
// The service must use the same key pair that was used to generate the token being verified.
//
// The following errors are returned by this function:
// JWTError
func (j *JWTAuthRSAService) VerifyToken(ctx context.Context, encodedToken string) (*jwt.Token, errorx.Error) {
	// parse the JWT token
	token, err := jwt.Parse(encodedToken, func(token *jwt.Token) (interface{}, error) {
		method, ok := token.Method.(*jwt.SigningMethodRSA)
		if !ok || strings.ToUpper(method.Alg()) != "RS256" {
			return nil, NewJWTErrorWithContext(ctx, "failed to validate JWT algorithm",
				fmt.Errorf("JWT algorithm '%s' does not match expected 'RS256' algorithm", token.Header["alg"])).
				WithAttr("jwt_alg", token.Header["alg"])
		}
		return j.publicKey, nil
	})
	if err != nil {
		return nil, NewJWTErrorWithContext(ctx, "failed to parse JWT", err)
	}
	return token, nil
}

// JWTAuthECDSAService creates and validates JWT tokens that are signed with a private ECDSA key and validated with a
// public ECDSA key.
type JWTAuthECDSAService struct {
	publicKey  *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey
}

// NewJWTAuthECDSAService creates an initializes a new service object.
func NewJWTAuthECDSAService(publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) *JWTAuthECDSAService {
	return &JWTAuthECDSAService{
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

// GenerateToken generates a new JWT token with the given claims.
//
// The following errors are returned by this function:
// JWTError
func (j *JWTAuthECDSAService) GenerateToken(ctx context.Context, claims jwt.Claims) (string, errorx.Error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signedToken, err := token.SignedString(j.privateKey)
	if err != nil {
		return "", NewJWTErrorWithContext(ctx, "failed to generate JWT", err)
	}
	return signedToken, nil
}

// VerifyToken parses and verifies the token string, returning the resulting JWT token for further validation.
//
// The service must use the same secret that was used to generate the token being verified.
//
// The following errors are returned by this function:
// JWTError
func (j *JWTAuthECDSAService) VerifyToken(ctx context.Context, encodedToken string) (*jwt.Token, errorx.Error) {
	// parse the JWT token
	token, err := jwt.Parse(encodedToken, func(token *jwt.Token) (interface{}, error) {
		method, ok := token.Method.(*jwt.SigningMethodECDSA)
		if !ok || strings.ToUpper(method.Alg()) != "ES256" {
			return nil, NewJWTErrorWithContext(ctx, "failed to validate JWT algorithm",
				fmt.Errorf("JWT algorithm '%s' does not match expected 'ES256' algorithm", token.Header["alg"])).
				WithAttr("jwt_alg", token.Header["alg"])
		}
		return j.publicKey, nil
	})
	if err != nil {
		return nil, NewJWTErrorWithContext(ctx, "failed to parse JWT", err)
	}
	return token, nil
}
