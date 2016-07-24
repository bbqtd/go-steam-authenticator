package authenticator

import (
	"encoding/base64"
	"errors"
)

var errInvalidSecret = errors.New("invalid secret")

func decodeSecret(secret string) ([]byte, error) {
	if secret == "" {
		return nil, errInvalidSecret
	}

	key, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, errInvalidSecret
	}

	return key, nil
}
