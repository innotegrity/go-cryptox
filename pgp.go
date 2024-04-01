package cryptox

import (
	"context"
	"errors"

	pmailcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
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
	kp := &PGPKeyPair{}

	// generate a new key
	key, err := pmailcrypto.GenerateKey(name, email, keyType, bits)
	if err != nil {
		return nil, NewPGPErrorWithContext(ctx, "failed to generate PGP key", err).
			WithAttrs(map[string]any{
				"name":     name,
				"email":    email,
				"key_type": keyType,
				"bits":     bits,
			})
	}
	kp.privateKey = key

	// encrypt the key with a random password
	kp.passphrase = GeneratePassword(32, 5, 5, 5)
	locked, err := key.Lock([]byte(kp.passphrase))
	if err != nil {
		return nil, NewPGPErrorWithContext(ctx, "failed to generate password for PGP key", err).
			WithAttrs(map[string]any{
				"name":     name,
				"email":    email,
				"key_type": keyType,
				"bits":     bits,
			})
	}
	armoredKey, err := locked.Armor()
	if err != nil {
		return nil, NewPGPErrorWithContext(ctx, "failed to armor PGP key", err).
			WithAttrs(map[string]any{
				"name":     name,
				"email":    email,
				"key_type": keyType,
				"bits":     bits,
			})
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
	kp := &PGPKeyPair{
		armoredKey: armoredKey,
		passphrase: passphrase,
	}

	// load the key
	key, err := pmailcrypto.NewKeyFromArmored(kp.armoredKey)
	if err != nil {
		return nil, NewPGPErrorWithContext(ctx, "failed to load armored key", err)
	}

	// check to see if the key is locked
	locked, err := key.IsLocked()
	if err != nil {
		return nil, NewPGPErrorWithContext(ctx, "failed to determine if key is locked", err)
	}
	if !locked {
		kp.privateKey = key
		return kp, nil
	}

	// unlock the key
	unlocked, err := key.Unlock([]byte(kp.passphrase))
	if err != nil {
		return nil, NewPGPErrorWithContext(ctx, "failed to unlock key", err)
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
	if kp.armoredKey == "" {
		return "", NewPGPErrorWithContext(ctx, "failed to load armored private key",
			errors.New("private key has not been initialized"))
	}
	return kp.armoredKey, nil
}

// GetArmoredPublicKey returns the public key wrapped in PGP armor.
//
// The following errors are returned by this function:
// ErrGetPGPKeyFailure
func (kp *PGPKeyPair) GetArmoredPublicKey(ctx context.Context) (string, error) {
	if kp.privateKey == nil { // should never happen
		return "", NewPGPErrorWithContext(ctx, "failed to load armored public key",
			errors.New("private key has not been initialized"))
	}
	key, err := kp.privateKey.GetArmoredPublicKey()
	if err != nil {
		return "", NewPGPErrorWithContext(ctx, "failed to load armored public key", err)
	}
	return key, nil
}
