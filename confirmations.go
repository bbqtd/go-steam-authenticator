package authenticator

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
)

const (
	acceptTradeTag      = "allow"
	cancelTag           = "cancel"
	loadConfirmationTag = "conf"
	tradeInfoTag        = "details"
)

// GenerateAcceptTradeCode generate and returns base64 encoded code for
// accepting trade.
//
// Identity Secret must be valid base64 encoded string otherwise error will be
// returnd. If timer is nil then CurrentTime() for evaluating time will be used.
func GenerateAcceptTradeCode(identitySecret string, timer func() uint64) (string, error) {
	key, err := decodeSecret(identitySecret)
	if err != nil {
		return "", ErrInvalidIdentitySecret
	}

	if timer == nil {
		timer = CurrentTime
	}

	return generateConfirmation(acceptTradeTag, key, timer()), nil
}

// GenerateCancelCode generate and returns base64 encoded code for canceling
// request.
//
// Identity Secret must be valid base64 encoded string otherwise error will be
// returnd. If timer is nil then CurrentTime() for evaluating time will be used.
func GenerateCancelCode(identitySecret string, timer func() uint64) (string, error) {
	key, err := decodeSecret(identitySecret)
	if err != nil {
		return "", ErrInvalidIdentitySecret
	}

	if timer == nil {
		timer = CurrentTime
	}

	return generateConfirmation(cancelTag, key, timer()), nil
}

// GenerateLoadConfirmationCode generate and returns base64 encoded code for
// loading confirmation.
//
// Identity Secret must be valid base64 encoded string otherwise error will be
// returnd. If timer is nil then CurrentTime() for evaluating time will be used.
func GenerateLoadConfirmationCode(identitySecret string, timer func() uint64) (string, error) {
	key, err := decodeSecret(identitySecret)
	if err != nil {
		return "", ErrInvalidIdentitySecret
	}

	if timer == nil {
		timer = CurrentTime
	}

	return generateConfirmation(loadConfirmationTag, key, timer()), nil
}

// GenerateTradeInfoCode generate and returns base64 encoded code for loading
// trade info.
//
// Identity Secret must be valid base64 encoded string otherwise error will be
// returnd. If timer is nil then CurrentTime() for evaluating time will be used.
func GenerateTradeInfoCode(identitySecret string, timer func() uint64) (string, error) {
	key, err := decodeSecret(identitySecret)
	if err != nil {
		return "", ErrInvalidIdentitySecret
	}

	if timer == nil {
		timer = CurrentTime
	}

	return generateConfirmation(tradeInfoTag, key, timer()), nil
}

// generateConfirmation generate and returns base64 confirmation code.
func generateConfirmation(tag string, key []byte, t uint64) string {
	bufcap := 8 + len(tag) // len(t) + len(tag)
	raw := make([]byte, 8, bufcap)

	binary.BigEndian.PutUint64(raw, t) // 00 00 00 00 [time]

	buf := bytes.NewBuffer(raw)
	buf.WriteString(tag)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf.Bytes())
	hash := mac.Sum(nil)

	return base64.StdEncoding.EncodeToString(hash)
}
