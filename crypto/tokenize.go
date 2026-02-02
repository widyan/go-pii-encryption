package crypto

import (
	"regexp"
	"strings"
)

var re = regexp.MustCompile(`[^a-z0-9]+`)

func Words(secret []byte, field string, value string) [][]byte {
	value = strings.ToLower(strings.TrimSpace(value))
	value = re.ReplaceAllString(value, " ")

	words := strings.Fields(value)
	seen := map[string]struct{}{}
	tokens := [][]byte{}

	for _, w := range words {
		if len(w) < 3 {
			continue
		}
		t := Token(secret, field+"|"+w)
		k := string(t)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		tokens = append(tokens, t)
	}
	return tokens
}

/*func DecryptOptional(enc *[]byte, key []byte) (*string, error) {
	if enc == nil {
		return nil, nil
	}

	plaintext, err := utils.DecryptAESGCM(*enc, key)
	if err != nil {
		return nil, err
	}

	s := string(plaintext)
	return &s, nil
}
*/
