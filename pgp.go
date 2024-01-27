package cryptox

import (
	"context"
	"errors"

	pmailcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	"go.innotegrity.dev/slogx"
)

// PGPKeyPair represents a PGP key pair.
type PGPKeyPair struct {
	armoredKey string
	passphrase string
	privateKey *pmailcrypto.Key
}

// NewPGPKeyPair returns a new PGP key pair.
//
// Be sure to call ClearPrivateParams on the returned key to clear memory out when finished with the object.
//
// The following errors are returned by this function:
// PGPError
func NewPGPKeyPair(ctx context.Context, name, email, keyType string, bits int) (*PGPKeyPair, error) {
	logger := slogx.ActiveLoggerFromContext(ctx)
	errAttr := slogx.ErrorAttrNameFromContext(ctx)
	kp := &PGPKeyPair{}

	// generate a new key
	key, err := pmailcrypto.GenerateKey(name, email, keyType, bits)
	if err != nil {
		e := NewPGPError("failed to generate PGP key", err)
		e.WithAttrs(map[string]any{
			"name":     name,
			"email":    email,
			"key_type": keyType,
			"bits":     bits,
		})
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return nil, e
	}
	kp.privateKey = key

	// encrypt the key with a random password
	kp.passphrase = GeneratePassword(32, 5, 5, 5)
	locked, err := key.Lock([]byte(kp.passphrase))
	if err != nil {
		e := NewPGPError("failed to generate password for PGP key", err)
		e.WithAttrs(map[string]any{
			"name":     name,
			"email":    email,
			"key_type": keyType,
			"bits":     bits,
		})
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return nil, e
	}
	armoredKey, err := locked.Armor()
	if err != nil {
		e := NewPGPError("failed to armor PGP key", err)
		e.WithAttrs(map[string]any{
			"name":     name,
			"email":    email,
			"key_type": keyType,
			"bits":     bits,
		})
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return nil, e
	}
	kp.armoredKey = armoredKey
	return kp, nil
}

// NewPGPKeyPairFromArmor returns a new PGP key pair from the given armored private key.
//
// Be sure to call ClearPrivateParams on the returned key to clear memory out when finished with the object.
//
// The following errors are returned by this function:
// PGPError
func NewPGPKeyPairFromArmor(ctx context.Context, armoredKey, passphrase string) (*PGPKeyPair, error) {
	logger := slogx.ActiveLoggerFromContext(ctx)
	errAttr := slogx.ErrorAttrNameFromContext(ctx)
	kp := &PGPKeyPair{
		armoredKey: armoredKey,
		passphrase: passphrase,
	}

	// load the key
	key, err := pmailcrypto.NewKeyFromArmored(kp.armoredKey)
	if err != nil {
		e := NewPGPError("failed to load armored key", err)
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return nil, e
	}

	// check to see if the key is locked
	locked, err := key.IsLocked()
	if err != nil {
		e := NewPGPError("failed to determine if key is locked", err)
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return nil, e
	}
	if !locked {
		kp.privateKey = key
		return kp, nil
	}

	// unlock the key
	unlocked, err := key.Unlock([]byte(kp.passphrase))
	if err != nil {
		e := NewPGPError("failed to unlock key", err)
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return nil, e
	}
	kp.privateKey = unlocked
	return kp, nil
}

// ClearPrivateParams clears out memory attached to the private key.
func (kp *PGPKeyPair) ClearPrivateParams() {
	if kp.privateKey != nil {
		kp.privateKey.ClearPrivateParams()
	}
}

// GetArmoredPrivateKey returns the private key wrapped in PGP armor.
//
// The following errors are returned by this function:
// PGPError
func (kp *PGPKeyPair) GetArmoredPrivateKey(ctx context.Context) (string, error) {
	logger := slogx.ActiveLoggerFromContext(ctx)
	errAttr := slogx.ErrorAttrNameFromContext(ctx)

	if kp.armoredKey == "" {
		e := NewPGPError("failed to load armored private key", errors.New("private key has not been initialized"))
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return "", e
	}
	return kp.armoredKey, nil
}

// GetArmoredPublicKey returns the public key wrapped in PGP armor.
//
// The following errors are returned by this function:
// ErrGetPGPKeyFailure
func (kp *PGPKeyPair) GetArmoredPublicKey(ctx context.Context) (string, error) {
	logger := slogx.ActiveLoggerFromContext(ctx)
	errAttr := slogx.ErrorAttrNameFromContext(ctx)

	if kp.privateKey == nil { // should never happen
		e := NewPGPError("failed to load armored public key", errors.New("private key has not been initialized"))
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return "", e
	}
	key, err := kp.privateKey.GetArmoredPublicKey()
	if err != nil {
		e := NewPGPError("failed to load armored public key", err)
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return "", e
	}
	return key, nil
}
