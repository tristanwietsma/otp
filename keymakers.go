package otp

import "strings"

func newKey(method, label, secret, issuer string, algo Hash, digits, period, counter int) (*Key, error) {

	k := Key{
		Method:  method,
		Label:   label,
		Secret:  strings.ToUpper(secret),
		Issuer:  issuer,
		Algo:    algo,
		Digits:  digits,
		Period:  period,
		Counter: counter,
	}

	if v, err := k.IsValid(); v != true {
		return &k, err
	}

	return &k, nil
}

// Returns a TOTP Key.
func NewTotp(label, secret, issuer string, algo Hash, digits, period int) (*Key, error) {
	k, err := newKey("totp", label, secret, issuer, algo, digits, period, 0)
	return k, err
}

// Returns a HOTP Key.
func NewHotp(label, secret, issuer string, algo Hash, digits, counter int) (*Key, error) {
	k, err := newKey("hotp", label, secret, issuer, algo, digits, 0, counter)
	return k, err
}
