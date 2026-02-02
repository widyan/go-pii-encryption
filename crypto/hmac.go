package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func Token(secret []byte, value string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(normalize(value)))
	return mac.Sum(nil)
}

func HMACString(key []byte, value string) string {
	token := Token(key, value)
	return hex.EncodeToString(token)
}
