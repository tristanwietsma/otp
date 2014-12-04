package otp

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
)

var methods = []string{"totp", "hotp"}

// Supported hash algorithms.
var Hashes = []Hash{sha1.New, sha256.New, sha512.New, md5.New}

// Key represents a one-time password. It supports time-based (totp) and HMAC-based (hotp) approaches.
type Key struct {
	Method  string // Initialization method. Either 'totp' or 'hotp'.
	Label   string // Descriptive label..
	Secret  string // Base32-encoded secret key.
	Issuer  string // Key issuer.
	Algo    Hash   // Hash algorithm. See Hashes.
	Digits  int    // Length of the code. Either 6 or 8.
	Period  int    // Seconds code is valid for. Applies only to 'totp'.
	Counter int    // Initial counter value. Applies only to 'hotp'.
}

// GetCode returns a one-time password code an initial value..
func (k Key) GetCode(iv int64) (string, error) {
	code, err := GetCode(k.Secret, iv, k.Algo, k.Digits)
	return code, err
}
