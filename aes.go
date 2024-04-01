package cryptox

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"go.innotegrity.dev/errorx"
)

// DecryptString decrypts the given block of ciphertext that was encrypted using the EncryptString() function.
//
// If the string was encrypted using a random key generated by EncryptString(), leave the key empty.
//
// The following errors are returned by this function:
// DecryptionError
func DecryptString(ctx context.Context, ciphertext, key string) (string, errorx.Error) {
	// decode the Base64-encoded string
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", NewDecryptionErrorWithContext(ctx, "failed to decode ciphertext string", err)
	}

	// extract the key, nonce and ciphertext
	cipherKey := []byte(key)
	var nonce []byte
	if key == "" {
		cipherKey = make([]byte, 32)
		nonce = make([]byte, 12)
		for i := 0; i < 44; i++ {
			if i < 8 {
				cipherKey[24+i] = data[i]
			} else if i >= 8 && i < 12 {
				nonce[i-8] = data[i]
			} else if i >= 12 && i < 20 {
				cipherKey[19-i+16] = data[i]
			} else if i >= 20 && i < 24 {
				nonce[i-12] = data[i]
			} else if i >= 24 && i < 32 {
				cipherKey[i-24] = data[i]
			} else if i >= 32 && i < 36 {
				nonce[35-i+4] = data[i]
			} else {
				cipherKey[43-i+8] = data[i]
			}
		}
		data = data[44:]
	} else {
		nonce = data[0:12]
		data = data[12:]
	}

	// hash the key
	sha := sha256.Sum256(cipherKey)

	// create a new cipher block from the key
	block, err := aes.NewCipher(sha[0:32])
	if err != nil {
		return "", NewDecryptionErrorWithContext(ctx, "failed to generate new cipher", err)
	}

	// create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", NewDecryptionErrorWithContext(ctx, "failed to generate GCM", err)
	}

	// decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, data, cipherKey)
	if err != nil {
		return "", NewDecryptionErrorWithContext(ctx, "failed to decrypt the data", err)
	}
	return string(plaintext), nil
}

// EncryptString encrypts the given string using the given key.
//
// If the key is empty, a random key is generated and stored with the ciphertext.
//
// The following errors are returned by this function:
// EncryptionError
func EncryptString(ctx context.Context, plaintext, key string) (string, errorx.Error) {
	// generate a random key if needed
	cipherKey := []byte(key)
	if key == "" {
		cipherKey = make([]byte, 32)
		if _, err := rand.Read(cipherKey); err != nil {
			return "", NewEncryptionErrorWithContext(ctx, "failed to generate random key", err)
		}
	}

	// hash the key
	sha := sha256.Sum256(cipherKey)

	// create a new cipher block from the key
	block, err := aes.NewCipher(sha[0:32])
	if err != nil {
		return "", NewEncryptionErrorWithContext(ctx, "failed to generate a new cipher", err)
	}

	// create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", NewEncryptionErrorWithContext(ctx, "failed to generate GCM", err)
	}

	// create a nonce from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", NewEncryptionErrorWithContext(ctx, "failed to generate nonce from GCM", err)
	}

	// encrypt the data and hide the key inside the ciphertext
	var data []byte
	if key == "" {
		ciphertext := aesGCM.Seal(nil, nonce, []byte(plaintext), cipherKey)
		data = cipherKey[24:32]
		data = append(data, nonce[0:4]...)
		data = append(data, reverseSlice(cipherKey[16:24])...)
		data = append(data, nonce[8:12]...)
		data = append(data, cipherKey[0:8]...)
		data = append(data, reverseSlice(nonce[4:8])...)
		data = append(data, reverseSlice(cipherKey[8:16])...)
		data = append(data, ciphertext...)
	} else {
		data = aesGCM.Seal(nonce, nonce, []byte(plaintext), cipherKey)
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// reverseSlice simply reverses the byte slice passed in and returns the reversed slice.
func reverseSlice(s []byte) []byte {
	r := make([]byte, len(s))
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = s[j], s[i]
	}
	return r
}
