package authenticator

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
)

// GenerateAuthCode generate and returns 5 symbols authentication code for Log In depended
// on Shared Secret and Timer.
//
// It's usefull when you need generate code only once.
//
// Shared Secret must be valid base64 string otherwise error will be returned.
// If timer is nil then CurrentTime() for evaluating time will be used.
func GenerateAuthCode(sharedSecret string, timer func() uint64) (string, error) {
	key, err := decodeSecret(sharedSecret)
	if err != nil {
		return "", ErrInvalidSharedSecret
	}

	if timer == nil {
		timer = CurrentTime
	}

	return generateAuthCode(key, timer()), nil
}

var (
	// Range of possible chars for auth code.
	codeChars = []byte{
		// 2, 3, 4, 5, 6, 7, 8, 9, B, C, D, F, G
		50, 51, 52, 53, 54, 55, 56, 57, 66, 67, 68, 70, 71,
		// H, J, K, M, N, P, Q, R, T, V, W, X, Y
		72, 74, 75, 77, 78, 80, 81, 82, 84, 86, 87, 88, 89,
	}

	// Cached length of possible chars.
	// (because Go don't do it this when slice is global variable)
	// http://stackoverflow.com/questions/26634554/go-multiple-len-calls-vs-performance
	codeCharsLen = len(codeChars)
)

// generateAuthCode generate and returns 5 symbols Steam Authentication code.
func generateAuthCode(key []byte, t uint64) string {
	t /= 30                           // converting time for any reason
	tb := make([]byte, 8)             // 00 00 00 00 00 00 00 00
	binary.BigEndian.PutUint64(tb, t) // 00 00 00 00 xx xx xx xx

	// evaluate hash code for `tb` by key
	mac := hmac.New(sha1.New, key)
	mac.Write(tb)
	hashcode := mac.Sum(nil)

	// last 4 bits provide initial position
	// len(hashcode) = 20 bytes
	start := hashcode[19] & 0xf

	// extract 4 bytes at `start` and drop first bit
	fc32 := binary.BigEndian.Uint32(hashcode[start : start+4])
	fc32 &= 1<<31 - 1
	fullcode := int(fc32)

	// generate auth code
	code := make([]byte, 5)
	for i := range code {
		code[i] = codeChars[fullcode%codeCharsLen]
		fullcode /= codeCharsLen
	}

	return string(code[:])
}
