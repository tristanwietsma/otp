package otp

import (
	_ "bytes"
	"encoding/base32"
	"errors"
	"strings"
	_ "text/template"
)

// Defines a secret key per otpauth specifications. See https://code.google.com/p/google-authenticator/wiki/KeyUriFormat for more information.
type KeyUri struct {
	method string
	label  string
	secret string
	issuer string
	algo   string
	digits int
	param  int64
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func newKey(method, label, secret, issuer, algo string, digits int, param int64) (*KeyUri, error) {

	// validate label
	if strings.ContainsRune(label, '/') {
		return &KeyUri{}, errors.New("Invalid `label`: Contains '/'.")
	}

	// validate secret
	secret = strings.ToUpper(secret)
	if _, err := base32.StdEncoding.DecodeString(secret); err != nil {
		return &KeyUri{}, errors.New("Invalid `secret`: Does not decode from Base32.")
	}

	// validate issuer
	if strings.ContainsRune(issuer, '/') {
		return &KeyUri{}, errors.New("Invalid `issuer`: Contains '/'.")
	}

	// validate algo
	algo = strings.ToUpper(algo)
	validAlgos := []string{"SHA1", "SHA256", "SHA512", "MD5"}
	if !stringInSlice(algo, validAlgos) {
		return &KeyUri{}, errors.New("Invalid `algo`: Only SHA1, SHA256, SHA512, MD5 are supported.")
	}

	// validate digits
	if !(digits == 6 || digits == 8) {
		return &KeyUri{}, errors.New("Invalid `digits`: Value must be 6 or 8.")
	}

	// validate period
	if method == "totp" && param < 0 {
		return &KeyUri{}, errors.New("Invalid `param`: For totp, value must be positive.")
	}

	key := KeyUri{
		method: method,
		label:  label,
		secret: secret,
		issuer: issuer,
		algo:   algo,
		digits: digits,
		param:  param,
	}
	return &key, nil
}

// Returns a TOTP KeyUri.
func NewTOTP(label, secret, issuer, algo string, digits int, param int64) (*KeyUri, error) {
	key, err := newKey("totp", label, secret, issuer, algo, digits, param)
	return key, err
}

// Returns a HOTP KeyUri.
func NewHOTP(label, secret, issuer, algo string, digits int, param int64) (*KeyUri, error) {
	key, err := newKey("hotp", label, secret, issuer, algo, digits, param)
	return key, err
}

/* Returns the string representation of the KeyUri.
func (k KeyUri) String() string {
	markup := "otpauth://{{.method}}/{{.label}}?secret={{.secret}}"
	tmpl, _ := template.New("uri").Parse(markup)
	var uri bytes.Buffer
	tmpl.Execute(&uri, k)
	return uri.String()
}*/
