package otp

import (
	"bytes"
	"encoding/base32"
	"errors"
	"strconv"
	"strings"
	"text/template"
)

var METHODS = []string{"totp", "hotp"}
var HASHES = []string{"SHA1", "SHA256", "SHA512", "MD5"}

// Defines a Secret key per otpauth specifications. See https://code.google.com/p/google-authenticator/wiki/KeyFormat for more information.
type Key struct {
	Method  string // Required.
	Label   string // Required.
	Secret  string // Required.
	Issuer  string // Optional.
	Algo    string // Optional.
	Digits  string // Optional.
	Period  string // Optional for TOTP.
	Counter string // Required for HOTP.
}

func (k Key) IsValid() (bool, string) {

	// validate method
	if !stringInSlice(k.Method, METHODS) {
		msg := "'Method' must match on of {" + strings.Join(METHODS, ", ") + "}."
		return false, msg
	}

	// validate label
	if k.Label == "" {
		return false, "'Label' is empty."
	}

	if strings.ContainsRune(k.Label, '/') {
		return false, "'Label' contains '/'."
	}

	// validate secret
	if k.Secret == "" {
		return false, "'Secret' is empty."
	}

	if k.Secret != strings.ToUpper(k.Secret) {
		return false, "'Secret' is not valid Base32; it contains lowercase characters."
	}

	if _, err := base32.StdEncoding.DecodeString(k.Secret); err != nil {
		return false, "'Secret' is not valid Base32; it does not decode."
	}

	// validate issuer
	if strings.ContainsRune(k.Issuer, '/') {
		return false, "'Issuer' contains '/'."
	}

	// validate algo
	if k.Algo != "" {
		if k.Algo != strings.ToUpper(k.Algo) {
			return false, "'Algo' contains lowercase characters."
		}

		if !stringInSlice(k.Algo, HASHES) {
			msg := "'Algo' must match one of {" + strings.Join(HASHES, ", ") + "}."
			return false, msg
		}
	}

	// validate digits
	if k.Digits != "" {
		if _, err := strconv.Atoi(k.Digits); err != nil {
			return false, "'Digits' must be an integer."
		}

		if !(k.Digits == "6" || k.Digits == "8") {
			return false, "'Digits' must be either 6 or 8."
		}
	}

	// validate period
	if k.Method == "totp" && k.Period != "" {
		period, err := strconv.Atoi(k.Period)
		if err != nil {
			return false, "'Period' must be an integer."
		}
		if period < 1 {
			return false, "Period must be a positive integer."
		}
	}

	// validate counter
	if k.Method == "hotp" {
		if k.Counter == "" {
			return false, "'Counter' is empty."
		}
		if _, err := strconv.Atoi(k.Counter); err != nil {
			return false, "'Counter' must be defined and an integer."
		}
	}

	return true, ""
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func newKey(method, label, secret, issuer, algo, digits, period, counter string) (*Key, error) {

	k := Key{
		Method:  method,
		Label:   label,
		Secret:  strings.ToUpper(secret),
		Issuer:  issuer,
		Algo:    strings.ToUpper(algo),
		Digits:  digits,
		Period:  period,
		Counter: counter,
	}

	if v, msg := k.IsValid(); v != true {
		return &k, errors.New(msg)
	}

	return &k, nil
}

// Returns a TOTP Key.
func NewTotp(label, secret, issuer, algo string, digits, period int) (*Key, error) {
	d := strconv.Itoa(digits)
	p := strconv.Itoa(period)
	k, err := newKey("totp", label, secret, issuer, algo, d, p, "")
	return k, err
}

// Returns a HOTP Key.
func NewHotp(label, secret, issuer, algo string, digits, counter int) (*Key, error) {
	d := strconv.Itoa(digits)
	c := strconv.Itoa(counter)
	k, err := newKey("hotp", label, secret, issuer, algo, d, "", c)
	return k, err
}

// Returns the string representation of the Key.
func (k Key) String() string {
	markup := "otpauth://{{.Method}}/{{.Label}}?Secret={{.Secret}}"
	if len(k.Issuer) > 0 {
		markup = markup + "&Issuer={{.Issuer}}"
	}

	if len(k.Algo) > 0 {
		markup = markup + "&Algo={{.Algo}}"
	}

	if k.Digits != "" {
		markup = markup + "&Digits={{.Digits}}"
	}

	if k.Method == "totp" && k.Period != "" {
		markup = markup + "&Period={{.Period}}"
	}

	if k.Method == "hotp" {
		markup = markup + "&Counter={{.Counter}}"
	}

	tmpl, _ := template.New("uri").Parse(markup)
	var uri bytes.Buffer
	tmpl.Execute(&uri, k)
	return uri.String()
}
