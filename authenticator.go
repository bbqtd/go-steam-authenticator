package authenticator

import (
	"errors"
	"time"
)

// ErrInvalidSharedSecret can be returned when shared secret isn't base64
// encoded string.
var ErrInvalidSharedSecret = errors.New("steam/authenticator: invalid base64 shared secret")

// ErrInvalidIdentitySecret can be returned when identity secret isn't base64
// encoded string.
var ErrInvalidIdentitySecret = errors.New("steam/authenticator: invalid base64 identity secret")

// CurrentTime returns current time in Unix format.
//
// In most cases you only need it. By default if a function receive nil timer then
// CurrentTime() will be used. This timer function is usefull when you need
// create a custom timer.
func CurrentTime() uint64 {
	return uint64(time.Now().Unix())
}

// Authenticator represent the Steam Guard Mobile Authenticator that provide
// generating codes.
type Authenticator struct {
	time func() uint64

	// Shared Secret
	b64ss string
	ss    []byte

	// Identity Secret
	b64is string
	is    []byte
}

// New returns a new Authenticator by shared secret and identity secret
//
// Shared Secret and Identity Secret is base64 string (like
// qhVFE32idZj+O84yXss5oj83fUE=) otherwise error returned. If timer is nil then
// CurrentTime() for evaluating time will be used.
func New(sharedSecret string, identitySecret string, timer func() uint64) (*Authenticator, error) {
	ss, err := decodeSecret(sharedSecret)
	if err != nil {
		return nil, ErrInvalidSharedSecret
	}

	is, err := decodeSecret(identitySecret)
	if err != nil {
		return nil, ErrInvalidIdentitySecret
	}

	if timer == nil {
		timer = CurrentTime
	}

	return &Authenticator{
		time: timer,

		b64ss: sharedSecret,
		ss:    ss,
		b64is: identitySecret,
		is:    is,
	}, nil
}

// AuthCode generate and returns 5 symbols Steam Authentication code for Log In.
func (a *Authenticator) AuthCode() string {
	return generateAuthCode(a.ss, a.time())
}

// AcceptTradeCode generate and returns base64 encoded code for accepting trade.
func (a *Authenticator) AcceptTradeCode() string {
	return generateConfirmation(acceptTradeTag, a.is, a.time())
}

// CancelCode generate and returns base64 encoded code for canceling.
func (a *Authenticator) CancelCode() string {
	return generateConfirmation(cancelTag, a.is, a.time())
}

// LoadConfirmationCode generate and returns base64 encoded code for loading
// confirmation.
func (a *Authenticator) LoadConfirmationCode() string {
	return generateConfirmation(loadConfirmationTag, a.is, a.time())
}

// TradeInfoCode generate and returns base64 encoded code for loading trade
// info.
func (a *Authenticator) TradeInfoCode() string {
	return generateConfirmation(tradeInfoTag, a.is, a.time())
}
