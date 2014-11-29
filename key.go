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

var METHODS = []string{"totp", "hotp"}
var HASHES = []string{"SHA1", "SHA256", "SHA512", "MD5"}

type KeyError struct {
	param string
	msg   string
}

func (e KeyError) Error() string {
	return fmt.Sprintf("KeyError - %v - %v", e.param, e.msg)
}

// Defines a key per otpauth specifications. See https://code.google.com/p/google-authenticator/wiki/KeyFormat for more information.
type Key struct {
	Method  string // Initialization method. Acceptable values are either 'totp' or 'hotp' for time-based or counter-based, respectively.
	Label   string // Label for the key.
	Secret  string // String representation of base32 encoded integer.
	Issuer  string // The issuer of the key.
	Algo    string // The hash algorithm used in the HMAC.
	Digits  int    // The length of the code. 6 or 8 are acceptable.
	Period  int    // The number of seconds the code is valid for. Applies only to 'totp'.
	Counter int    // The initial counter value. Applies only to 'hotp'.
}

func (k Key) GetHotpCode(iv int64) (string, error) {
	var h hashFunc
	if k.Algo == "SHA1" {
		h = sha1.New
	} else if k.Algo == "SHA256" {
		h = sha256.New
	} else if k.Algo == "SHA512" {
		h = sha512.New
	} else {
		h = md5.New
	}
	code, err := GetCode(k.Secret, iv, h, k.Digits)
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
		keyErr := KeyError{
			"Method",
			"Must match one of {" + strings.Join(METHODS, ", ") + "}",
		}
		return false, keyErr
	}

	/*
	   check label
	*/

	if len(k.Label) == 0 {
		keyErr := KeyError{
			"Label",
			"Missing",
		}
		return false, keyErr
	}

	if strings.ContainsRune(k.Label, '/') {
		keyErr := KeyError{
			"Label",
			"Contains forward slash",
		}
		return false, keyErr
	}

	/*
	   check secret
	*/

	if len(k.Secret) == 0 {
		keyErr := KeyError{
			"Secret",
			"Missing",
		}
		return false, keyErr
	}

	if _, err := base32.StdEncoding.DecodeString(k.Secret); err != nil {
		keyErr := KeyError{
			"Secret",
			"Invalid Base32",
		}
		return false, keyErr
	}

	/*
	   check issuer
	*/

	if strings.ContainsRune(k.Issuer, '/') {
		keyErr := KeyError{
			"Issuer",
			"Contains forward slash",
		}
		return false, keyErr
	}

	/*
	   check algo
	*/

	if !stringInSlice(k.Algo, HASHES) {
		keyErr := KeyError{
			"Algo",
			"Must match one of {" + strings.Join(HASHES, ", ") + "}",
		}
		return false, keyErr
	}

	/*
	   check digits
	*/

	if !(k.Digits == 6 || k.Digits == 8) {
		keyErr := KeyError{
			"Digits",
			"Must be either 6 o 8",
		}
		return false, keyErr
	}

	/*
	   check period
	*/

	if k.Method == "totp" && k.Period < 1 {
		keyErr := KeyError{
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

	markup = markup + "&Algo={{.Algo}}&Digits={{.Digits}}"

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
