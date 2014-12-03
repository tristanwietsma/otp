package otp

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
)

// Supported values for `Key.Method`.
var METHODS = []string{"totp", "hotp"}

// Supported values algorithms for `Key.Algo`.
var HASHES = []Hash{sha1.New, sha256.New, sha512.New, md5.New}

// Key defines a set of parameters required for code generation as well as metadata.
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

// GetCode accepts an initialization value and returns a corresponding code.
func (k Key) GetCode(iv int64) (string, error) {
	code, err := GetCode(k.Secret, iv, k.Algo, k.Digits)
	return code, err
}
