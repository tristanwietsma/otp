package otp

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

// Supported values for `Key.Method`.
var METHODS = []string{"totp", "hotp"}

// Supported values algorithms for `Key.Algo`.
var HASHES = []Hash{sha1.New, sha256.New, sha512.New, md5.New}

var (
	keyURIregex = regexp.MustCompile(
		`^otpauth:\/\/(totp|hotp)\/([^\/?]*)\?.*secret=([A-Z2-7]*)(?:&|$)`)
	issuerRegex = regexp.MustCompile(
		`\?.*issuer=([^\/?]*)(?:&|$)`)
	algoRegex = regexp.MustCompile(
		`\?.*algo=(SHA1|SHA256|SHA512|MD5)(?:&|$)`)
	digitsRegex = regexp.MustCompile(
		`\?.*digits=(6|8)(?:&|$)`)
	periodRegex = regexp.MustCompile(
		`totp.*\?.*period=([0-9]*)(?:&|$)`)
	counterRegex = regexp.MustCompile(
		`hotp.*\?.*counter=([0-9]*)(?:&|$)`)
)

// Defines set of parameters required for code generation, including metadata.
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
func (k Key) GetCode(iv int64) (string, error) {
	code, err := GetCode(k.Secret, iv, k.Algo, k.Digits)
	return code, err
}

func (k Key) hasValidMethod() error {
	if !stringInSlice(k.Method, METHODS) {
		return KeyError{"Method", "Invalid value"}
	}
	return nil
}

func (k Key) hasValidLabel() error {
	if len(k.Label) == 0 {
		return KeyError{"Label", "Missing value"}
	}

	if strings.ContainsRune(k.Label, '/') {
		return KeyError{"Label", "Contains '/'"}
	}

	return nil
}

func (k Key) hasValidSecret() error {
	if len(k.Secret) == 0 {
		return KeyError{"Secret", "Missing value"}
	}

	if _, err := base32.StdEncoding.DecodeString(k.Secret); err != nil {
		return KeyError{"Secret", "Invalid Base32"}
	}

	return nil
}

func (k Key) hasValidIssuer() error {
	if strings.ContainsRune(k.Issuer, '/') {
		return KeyError{"Issuer", "Contains '/'"}
	}
	return nil
}

func (k Key) hasValidAlgo() error {
	if !hashInSlice(k.Algo, HASHES) {
		return KeyError{"Algo", "Invalid hashing algorithm"}
	}
	return nil
}

func (k Key) hasValidDigits() error {
	if !(k.Digits == 6 || k.Digits == 8) {
		return KeyError{"Digits", "Not equal to 6 or 8"}
	}
	return nil
}

func (k Key) hasValidPeriod() error {
	if k.Method == "totp" && k.Period < 1 {
		return KeyError{"Period", "Negative value"}
	}
	return nil
}

func (k Key) IsValid() (bool, error) {

	// check method
	if err := k.hasValidMethod(); err != nil {
		return false, err
	}

	//check label
	if err := k.hasValidLabel(); err != nil {
		return false, err
	}

	// check secret
	if err := k.hasValidSecret(); err != nil {
		return false, err
	}

	// check issuer
	if err := k.hasValidIssuer(); err != nil {
		return false, err
	}

	// check algo
	if err := k.hasValidAlgo(); err != nil {
		return false, err
	}

	// check digits
	if err := k.hasValidDigits(); err != nil {
		return false, err
	}

	// check period
	if err := k.hasValidPeriod(); err != nil {
		return false, err
	}

	return true, nil
}

// Returns the string representation of the Key according to the Google Authenticator KeyUriFormat. See https://code.google.com/p/google-authenticator/wiki/KeyUriFormat for more detail.
func (k Key) ToURI() string {
	markup := "otpauth://{{.Method}}/{{.Label}}?secret={{.Secret}}"
	if len(k.Issuer) > 0 {
		markup = markup + "&issuer={{.Issuer}}"
	}

	// reflect out the name of the hash function
	hashName := strings.Split(strings.Split(getFuncName(k.Algo), ".")[0], "/")[1]
	markup = markup + "&algo=" + strings.ToUpper(hashName)

	markup = markup + "&digits={{.Digits}}"

	if k.Method == "totp" {
		markup = markup + "&period={{.Period}}"
	}

	if k.Method == "hotp" {
		markup = markup + "&counter={{.Counter}}"
	}

	tmpl, _ := template.New("uri").Parse(markup)
	var uri bytes.Buffer
	tmpl.Execute(&uri, k)
	return uri.String()
}

func (k *Key) FromURI(uri string) error {

	// requirements
	if !keyURIregex.MatchString(uri) {
		return KeyError{"FromURI", "Invalid format."}
	}
	groups := keyURIregex.FindStringSubmatch(uri)
	(*k).Method = groups[1]
	(*k).Label = groups[2]
	(*k).Secret = groups[3]

	// issuer
	groups = issuerRegex.FindStringSubmatch(uri)
	if len(groups) == 1 {
		(*k).Issuer = groups[0]
	}

	// try to get algo; else default to SHA1
	groups = algoRegex.FindStringSubmatch(uri)
	if len(groups) == 1 {
		switch groups[0] {
		case "SHA1":
			(*k).Algo = sha1.New
		case "SHA256":
			(*k).Algo = sha256.New
		case "SHA512":
			(*k).Algo = sha512.New
		case "MD5":
			(*k).Algo = md5.New
		}
	} else {
		(*k).Algo = sha1.New
	}

	// try to digits; else 6
	groups = digitsRegex.FindStringSubmatch(uri)
	if len(groups) == 1 {
		(*k).Digits, _ = strconv.Atoi(groups[0])
	} else {
		(*k).Digits = 6
	}

	// if totp, try to get a period; else default to 30
	groups = periodRegex.FindStringSubmatch(uri)
	if len(groups) == 1 {
		(*k).Period, _ = strconv.Atoi(groups[0])
	} else {
		(*k).Period = 30
	}

	// if hotp, try to get a counter
	groups = counterRegex.FindStringSubmatch(uri)
	if len(groups) == 1 {
		(*k).Counter, _ = strconv.Atoi(groups[0])
	}

	return nil
}
