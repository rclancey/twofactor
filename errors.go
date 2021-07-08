package twofactor

import (
	"errors"
)

var ErrEmptyPassword = errors.New("empty password")
var ErrPasswordTooSimple = errors.New("password too simple")
var ErrInvalidResetCode = errors.New("invalid reset code")
var ErrTwoFactorNotConfigured = errors.New("two factor authentication not configured")
var ErrInvalid2FACode = errors.New("invalid two factor authentication code")
