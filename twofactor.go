package twofactor

import (
	"database/sql/driver"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/dgryski/dgoogauth"
	"github.com/nbutton23/zxcvbn-go"
	"github.com/pkg/errors"
	"github.com/gofrs/uuid/v3"
	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	Password         string     `json:"password"`
	ResetCode        *string    `json:"reset_code"`
	ResetCodeExpires *time.Time `json:"reset_code_expires"`
	TwoFactor        *TwoFactor `json:"two_factor"`
	InitTwoFactor    *TwoFactor `json:"init_two_factor"`
	dirty            bool
}

func NewAuth(password string, inputs ...string) (*Auth, error) {
	a := &Auth{}
	err := a.SetPassword(password, inputs...)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Auth) IsDirty() bool {
	return a.dirty
}

func (a *Auth) Value() (driver.Value, error) {
	data, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	return string(data), nil
}

func (a *Auth) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case string:
		return json.Unmarshal([]byte(v), a)
	case []byte:
		return json.Unmarshal(v, a)
	}
	return errors.Errorf("don't know how to convert %T into %T", value, *a)
}

func (a *Auth) SetPassword(password string, inputs ...string) error {
	if password == "" {
		return errors.WithStack(ErrEmptyPassword)
	}
	score := zxcvbn.PasswordStrength(password, inputs)
	if score.Score < 3 {
		return errors.WithStack(ErrPasswordTooSimple)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 0)
	if err != nil {
		return errors.Wrap(err, "can't hash password")
	}
	a.Password = string(hash)
	a.ResetCode = nil
	a.ResetCodeExpires = nil
	a.dirty = true
	return nil
}

func (a *Auth) CheckPassword(password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(a.Password), []byte(password))
	return errors.WithStack(err)
}

func (a *Auth) ResetPassword(dur time.Duration) (string, error) {
	data := make([]byte, 25)
	_, err := rand.Read(data)
	if err != nil {
		return "", errors.Wrap(err, "can't make reset token")
	}
	code := base32.StdEncoding.EncodeToString(data)
	expires := time.Now().Add(dur).UTC()
	a.ResetCode = &code
	a.ResetCodeExpires = &expires
	a.dirty = true
	return code, nil
}

func (a *Auth) CheckResetCode(code string) error {
	if a.ResetCode == nil || a.ResetCodeExpires == nil {
		return errors.WithStack(ErrInvalidResetCode)
	}
	if a.ResetCodeExpires.Before(time.Now()) {
		a.ResetCode = nil
		a.ResetCodeExpires = nil
		a.dirty = true
		return errors.WithStack(ErrInvalidResetCode)
	}
	if code != *a.ResetCode {
		return errors.WithStack(ErrInvalidResetCode)
	}
	return nil
}

func (a *Auth) Get2FACode() string {
	if a.TwoFactor == nil {
		return ""
	}
	return a.TwoFactor.GenCode()
}

func (a *Auth) Check2FA(code string) error {
	if a.TwoFactor == nil {
		return nil
	}
	rec := a.TwoFactor.ConsumeRecoveryKey(code)
	if rec {
		a.dirty = true
		return nil
	}
	return a.TwoFactor.Auth(code)
}

func (a *Auth) Has2FA() bool {
	return a.TwoFactor != nil
}

func (a *Auth) init2FA() error {
	tf, err := NewTwoFactor()
	if err != nil {
		return err
	}
	a.InitTwoFactor = tf
	a.dirty = true
	return nil
}

func (a *Auth) Configure2FA(username, domain string) (uri string, recoveryKeys []string, err error) {
	err = a.init2FA()
	if err != nil {
		return
	}
	uri = a.InitTwoFactor.Configure(username, domain)
	recoveryKeys = a.InitTwoFactor.RecoveryKeys
	return
}

func (a *Auth) Complete2FA(code string) error {
	if a.InitTwoFactor == nil {
		return errors.WithStack(ErrTwoFactorNotConfigured)
	}
	err := a.InitTwoFactor.Auth(code)
	if err != nil {
		return err
	}
	a.TwoFactor = a.InitTwoFactor
	a.InitTwoFactor = nil
	a.dirty = true
	return nil
}

type TwoFactor struct {
	Secret       string   `json:"secret"`
	RecoveryKeys []string `json:"recovery_keys"`
}

func NewTwoFactor() (*TwoFactor, error) {
	secretBytes := make([]byte, 10)
	n, err := rand.Read(secretBytes)
	if err != nil {
		return nil, errors.Wrap(err, "can't generate secret")
	}
	if n < len(secretBytes) {
		return nil, errors.New("can't generate secret: not enough system entropy")
	}
	secret := base32.StdEncoding.EncodeToString(secretBytes)
	recoveryCodes := make([]string, 8)
	var code uuid.UUID
	for i := range recoveryCodes {
		code, err = uuid.NewV4()
		if err != nil {
			return nil, errors.Wrap(err, "can't generate recovery codes")
		}
		recoveryCodes[i] = code.String()
	}
	return &TwoFactor{
		Secret: secret,
		RecoveryKeys: recoveryCodes,
	}, nil
}

func (tf *TwoFactor) Configure(username, domain string) string {
	config := &dgoogauth.OTPConfig{
		Secret: tf.Secret,
		WindowSize: 2,
		HotpCounter: 0,
		DisallowReuse: nil,
		ScratchCodes: nil,
		UTC: true,
	}
	return config.ProvisionURIWithIssuer(username, domain)
}

func (tf *TwoFactor) Complete(code string) error {
	config := &dgoogauth.OTPConfig{
		Secret: tf.Secret,
		WindowSize: 2,
		HotpCounter: 0,
		DisallowReuse: nil,
		ScratchCodes: nil,
		UTC: true,
	}
	ok, err := config.Authenticate(code)
	if err != nil {
		return errors.WithStack(err)
	}
	if !ok {
		return errors.WithStack(ErrInvalid2FACode)
	}
	return nil
}

func (tf *TwoFactor) GenCode() string {
	t := int64(time.Now().UTC().Unix() / 30)
	code := dgoogauth.ComputeCode(tf.Secret, t)
	return fmt.Sprintf("%06d", code)
}

func (tf *TwoFactor) ConsumeRecoveryKey(code string) bool {
	keep := []string{}
	found := false
	for _, rec := range tf.RecoveryKeys {
		if rec == code {
			found = true
		} else {
			keep = append(keep, rec)
		}
	}
	if found {
		tf.RecoveryKeys = keep
		return true
	}
	return false
}

func (tf *TwoFactor) Auth(code string) error {
	config := &dgoogauth.OTPConfig{
		Secret: tf.Secret,
		WindowSize: 5,
		HotpCounter: 0,
		DisallowReuse: nil,
		ScratchCodes: nil,
		UTC: true,
	}
	ok, err := config.Authenticate(code)
	if err != nil {
		return errors.WithStack(err)
	}
	if !ok {
		return errors.WithStack(ErrInvalid2FACode)
	}
	return nil
}
