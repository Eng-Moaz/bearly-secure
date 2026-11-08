package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

type EncryptedPayload struct {
	Nonce []byte
	AuthTag []byte
	Ciphertext []byte
}

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	return EncryptedPayload{
		Ciphertext: sealed[:len(sealed)-aead.Overhead()],
		AuthTag: sealed[len(sealed)-aead.Overhead():],
		Nonce: nonce,
	}, nil
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return []byte{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}
	if (len(payload.Nonce) != aead.NonceSize()) || (len(payload.AuthTag) != aead.Overhead()) {
		return []byte{}, errors.New("payload has no correct data")
	}
	var sealed []byte
	sealed = append(sealed, payload.Ciphertext...)
	sealed = append(sealed, payload.AuthTag...)
	plaintext, err := aead.Open(nil, payload.Nonce, sealed, nil)
	if err != nil {
		return []byte{}, err
	}
	return plaintext, nil
}
