package otp

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

var (
	keyURIregex = regexp.MustCompile(
		`^otpauth:\/\/(totp|hotp)\/([^\/?]*)\?.*secret=([A-Z2-7]*)(?:&.*|$)`)
	issuerRegex = regexp.MustCompile(
		`issuer=([^\/&]*)`)
	algoRegex = regexp.MustCompile(
		`(?:&|\?)algo=(SHA1|SHA256|SHA512|MD5|sha1|sha256|sha512|md5)(?:&|$)`)
	digitsRegex = regexp.MustCompile(
		`(?:&|\?)digits=([0-9]*)(?:&|$)`)
	validDigitsRegex = regexp.MustCompile(
		`(?:&|\?)digits=(6|8)(?:&|$)`)
	periodRegex = regexp.MustCompile(
		`totp.*(?:&|\?)period=([0-9]*)(?:&|$)`)
	counterRegex = regexp.MustCompile(
		`hotp.*(?:&|\?)counter=([0-9]*)(?:&|$)`)
)

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

// Parse OTPAUTH URI into Key attributes.
func (k *Key) FromURI(uri string) error {

	// requirements
	if !keyURIregex.MatchString(uri) {
		return KeyError{"FromURI", "Invalid format: missing."}
	}

	if strings.Count(uri, "/") != 3 {
		return KeyError{"FromURI", "Invalid format: wrong # of '/'"}
	}

	groups := keyURIregex.FindStringSubmatch(uri)
	(*k).Method = groups[1]
	(*k).Label = groups[2]
	(*k).Secret = groups[3]

	// issuer
	groups = issuerRegex.FindStringSubmatch(uri)
	if len(groups) == 2 {
		(*k).Issuer = groups[1]
	}

	// try to get algo; else default to SHA1
	groups = algoRegex.FindStringSubmatch(uri)
	if len(groups) == 2 {
		switch strings.ToUpper(groups[1]) {
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
	if len(groups) == 2 {
		groups = validDigitsRegex.FindStringSubmatch(uri)
		if len(groups) == 2 {
			(*k).Digits, _ = strconv.Atoi(groups[1])
		} else {
			return KeyError{"FromURI", "6 or 8 digits are valid"}
		}
	} else {
		(*k).Digits = 6
	}

	// if totp, try to get a period; else default to 30
	groups = periodRegex.FindStringSubmatch(uri)
	if len(groups) == 2 {
		(*k).Period, _ = strconv.Atoi(groups[1])
	} else {
		(*k).Period = 30
	}

	// if hotp, try to get a counter
	groups = counterRegex.FindStringSubmatch(uri)
	if len(groups) == 2 {
		(*k).Counter, _ = strconv.Atoi(groups[1])
	}

	return nil
}
