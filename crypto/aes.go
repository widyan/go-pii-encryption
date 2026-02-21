package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

type Encryption struct {
	AESKey  []byte
	HMACKey []byte
}

func NewEncryption(aesKey, hmacKey []byte) *Encryption {
	return &Encryption{AESKey: aesKey, HMACKey: hmacKey}
}

func (e *Encryption) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.AESKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (e *Encryption) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.AESKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("cipher too short")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	data := ciphertext[gcm.NonceSize():]

	return gcm.Open(nil, nonce, data, nil)
}

func (e *Encryption) EncryptString(plaintext string) ([]byte, error) {
	return Encrypt(e.AESKey, []byte(plaintext))
}

func (e *Encryption) MustEncryptString(plaintext string) []byte {
	enc, err := EncryptString(e.AESKey, plaintext)
	if err != nil {
		panic(err)
	}
	return enc
}

func (e *Encryption) DecryptString(ciphertext []byte) (string, error) {
	plain, err := Decrypt(e.AESKey, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (e *Encryption) MustDecryptString(ciphertext []byte) string {
	s, err := DecryptString(e.AESKey, ciphertext)
	if err != nil {
		panic(err)
	}
	return s
}

func (e *Encryption) DecryptOptional(enc *[]byte) (*string, error) {
	if enc == nil {
		return nil, nil
	}

	plain, err := Decrypt(e.AESKey, *enc)
	if err != nil {
		return nil, err
	}

	s := string(plain)
	return &s, nil
}

func (e *Encryption) EncryptOptionalString(
	value *string,
) ([]byte, error) {
	if value == nil || *value == "" {
		return nil, nil
	}
	return EncryptString(e.AESKey, *value)
}
