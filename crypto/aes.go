package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

func Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

func EncryptString(key []byte, plaintext string) ([]byte, error) {
	return Encrypt(key, []byte(plaintext))
}

func MustEncryptString(key []byte, plaintext string) []byte {
	enc, err := EncryptString(key, plaintext)
	if err != nil {
		panic(err)
	}
	return enc
}

func DecryptString(key, ciphertext []byte) (string, error) {
	plain, err := Decrypt(key, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func MustDecryptString(key, ciphertext []byte) string {
	s, err := DecryptString(key, ciphertext)
	if err != nil {
		panic(err)
	}
	return s
}

func DecryptOptional(enc *[]byte, key []byte) (*string, error) {
	if enc == nil {
		return nil, nil
	}

	plain, err := Decrypt(key, *enc)
	if err != nil {
		return nil, err
	}

	s := string(plain)
	return &s, nil
}

func EncryptOptionalString(
	key []byte,
	value *string,
) ([]byte, error) {
	if value == nil || *value == "" {
		return nil, nil
	}
	return EncryptString(key, *value)
}
