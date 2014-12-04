package otp

import "strings"

func newKey(method, label, secret, issuer string, algo Hash, digits, period, counter int) (*Key, error) {

	k := Key{
		Method:   method,
		Label:    label,
		Secret32: strings.ToUpper(secret),
		Issuer:   issuer,
		Algo:     algo,
		Digits:   digits,
		Period:   period,
		Counter:  counter,
	}

	if err := k.Validate(); err != nil {
		return &k, err
	}

	return &k, nil
}

// NewTOTPKey returns a totp key struct.
func NewTOTPKey(label, secret32, issuer string, algo Hash, digits, period int) (*Key, error) {
	k, err := newKey("totp", label, secret32, issuer, algo, digits, period, 0)
	return k, err
}

// NewHOTPKey returns a hotp key struct.
func NewHOTPKey(label, secret32, issuer string, algo Hash, digits, counter int) (*Key, error) {
	k, err := newKey("hotp", label, secret32, issuer, algo, digits, 0, counter)
	return k, err
}

// NewKey returns a new Key from an otpauth URI.
func NewKey(uri string) (*Key, error) {
	k := Key{}
	if err := k.FromURI(uri); err != nil {
		return &k, err
	}

	if err := k.Validate(); err != nil {
		return &k, err
	}

	return &k, nil
}
