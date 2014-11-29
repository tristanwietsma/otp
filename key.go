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

// List of valid methods.
var METHODS = []string{"totp", "hotp"}

// List of valid hash functions.
var HASHES = []Hash{sha1.New, sha256.New, sha512.New, md5.New}

type keyError struct {
	param string
	msg   string
}

func (e keyError) Error() string {
	return fmt.Sprintf("keyError - %v - %v", e.param, e.msg)
}

// Defines a key per otpauth specifications. See https://code.google.com/p/google-authenticator/wiki/KeyFormat for more information.
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

func (k Key) GetHotpCode(iv int64) (string, error) {
	code, err := GetCode(k.Secret, iv, k.Algo, k.Digits)
	return code, err
}

func (k Key) GetTotpCode() (string, error) {
	iv := GetInterval(int64(k.Period))
	code, err := k.GetHotpCode(iv)
	return code, err
}

func (k Key) IsValid() (bool, error) {

	/*
	   check method
	*/

	if !stringInSlice(k.Method, METHODS) {
		keyErr := keyError{
			"Method",
			"Must match one of {" + strings.Join(METHODS, ", ") + "}",
		}
		return false, keyErr
	}

	/*
	   check label
	*/

	if len(k.Label) == 0 {
		keyErr := keyError{
			"Label",
			"Missing",
		}
		return false, keyErr
	}

	if strings.ContainsRune(k.Label, '/') {
		keyErr := keyError{
			"Label",
			"Contains forward slash",
		}
		return false, keyErr
	}

	/*
	   check secret
	*/

	if len(k.Secret) == 0 {
		keyErr := keyError{
			"Secret",
			"Missing",
		}
		return false, keyErr
	}

	if _, err := base32.StdEncoding.DecodeString(k.Secret); err != nil {
		keyErr := keyError{
			"Secret",
			"Invalid Base32",
		}
		return false, keyErr
	}

	/*
	   check issuer
	*/

	if strings.ContainsRune(k.Issuer, '/') {
		keyErr := keyError{
			"Issuer",
			"Contains forward slash",
		}
		return false, keyErr
	}

	/*
	   check algo
	*/

	if !hashInSlice(k.Algo, HASHES) {
		keyErr := keyError{
			"Algo",
			"Must match one of {sha1, sha256, sha512, md5}",
		}
		return false, keyErr
	}

	/*
	   check digits
	*/

	if !(k.Digits == 6 || k.Digits == 8) {
		keyErr := keyError{
			"Digits",
			"Must be either 6 o 8",
		}
		return false, keyErr
	}

	/*
	   check period
	*/

	if k.Method == "totp" && k.Period < 1 {
		keyErr := keyError{
			"Period",
			"Must be positive",
		}
		return false, keyErr
	}

	return true, nil
}

// Returns the string representation of the Key.
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
