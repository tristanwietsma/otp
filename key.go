package otp

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"strings"
	"text/template"
)

// These are acceptable inputs for `Key.Method`.
var METHODS = []string{"totp", "hotp"}

// There are supported hash algorithms for `Key.Algo`.
var HASHES = []Hash{sha1.New, sha256.New, sha512.New, md5.New}

// Custom error type for Key related errors. Generally refers to validation errors.
type KeyError struct {
	param string
	msg   string
}

// Renders the error string.
func (e KeyError) Error() string {
	return fmt.Sprintf("KeyError - %v - %v", e.param, e.msg)
}

// Defines all parameter required for code generation, including useful metadata.
type Key struct {
	Method  string // Initialization method. Acceptable values are either 'totp' or 'hotp' for time-based or counter-based, respectively.
	Label   string // Label for the key.
	Secret  string // String representation of base32 encoded integer.
	Issuer  string // The issuer of the key.
	Algo    Hash   // The hash algorithm used in the HMAC. SHA1, SHA256, SHA512, and MD5 are supported.
	Digits  int    // The length of the code. 6 or 8 are acceptable.
	Period  int    // The number of seconds the code is valid for. Applies only to 'totp'.
	Counter int    // The initial counter value. Applies only to 'hotp'.
}

// Given an initialization value, returns the proscribed HMAC one-time password.
func (k Key) GetHOTPCode(iv int64) (string, error) {
	code, err := GetCode(k.Secret, iv, k.Algo, k.Digits)
	return code, err
}

// Using the current time and parameters defined by the key, returns the one-time password based on Unix system time.
func (k Key) GetTOTPCode() (string, error) {
	iv := GetInterval(int64(k.Period))
	code, err := k.GetHOTPCode(iv)
	return code, err
}

func (k Key) HasValidMethod() error {
	if !stringInSlice(k.Method, METHODS) {
		return KeyError{"Method", "Invalid value"}
	}
	return nil
}

func (k Key) HasValidLabel() error {
	if len(k.Label) == 0 {
		return KeyError{"Label", "Missing value"}
	}

	if strings.ContainsRune(k.Label, '/') {
		return KeyError{"Label", "Contains '/'"}
	}

	return nil
}

func (k Key) HasValidSecret() error {
	if len(k.Secret) == 0 {
		return KeyError{"Secret", "Missing value"}
	}

	if _, err := base32.StdEncoding.DecodeString(k.Secret); err != nil {
		return KeyError{"Secret", "Invalid Base32"}
	}

	return nil
}

func (k Key) HasValidIssuer() error {
	if strings.ContainsRune(k.Issuer, '/') {
		return KeyError{"Issuer", "Contains '/'"}
	}
	return nil
}

func (k Key) HasValidAlgo() error {
	if !hashInSlice(k.Algo, HASHES) {
		return KeyError{"Algo", "Invalid hashing algorithm"}
	}
	return nil
}

func (k Key) HasValidDigits() error {
	if !(k.Digits == 6 || k.Digits == 8) {
		return KeyError{"Digits", "Not equal to 6 or 8"}
	}
	return nil
}

func (k Key) HasValidPeriod() error {
	if k.Method == "totp" && k.Period < 1 {
		return KeyError{"Period", "Negative value"}
	}
	return nil
}

func (k Key) IsValid() (bool, error) {

	// check method
	if err := k.HasValidMethod(); err != nil {
		return false, err
	}

	//check label
	if err := k.HasValidLabel(); err != nil {
		return false, err
	}

	// check secret
	if err := k.HasValidSecret(); err != nil {
		return false, err
	}

	// check issuer
	if err := k.HasValidIssuer(); err != nil {
		return false, err
	}

	// check algo
	if err := k.HasValidAlgo(); err != nil {
		return false, err
	}

	// check digits
	if err := k.HasValidDigits(); err != nil {
		return false, err
	}

	// check period
	if err := k.HasValidPeriod(); err != nil {
		return false, err
	}

	return true, nil
}

// Returns the string representation of the Key according to the Google Authenticator KeyUriFormat. See https://code.google.com/p/google-authenticator/wiki/KeyUriFormat for more detail.
func (k Key) String() string {
	markup := "otpauth://{{.Method}}/{{.Label}}?Secret={{.Secret}}"
	if len(k.Issuer) > 0 {
		markup = markup + "&Issuer={{.Issuer}}"
	}

	// reflect out the name of the hash function
	hashName := strings.Split(strings.Split(getFuncName(k.Algo), ".")[0], "/")[1]
	markup = markup + "&Algo=" + strings.ToUpper(hashName)

	markup = markup + "&Digits={{.Digits}}"

	if k.Method == "totp" {
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
