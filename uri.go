package otp

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// Returns the string representation of the Key according to the Google Authenticator KeyUriFormat. See https://code.google.com/p/google-authenticator/wiki/KeyUriFormat for more detail.
func (k Key) ToURI() string {
	uri := url.URL{
		Scheme: "otpauth",
		Host:   k.Method,
		Path:   "/" + k.Label,
	}

	params := url.Values{}
	params.Set("secret", k.Secret)

	if k.Issuer != "" {
		params.Set("issuer", k.Issuer)
	}

	hashName := strings.Split(strings.Split(getFuncName(k.Algo), ".")[0], "/")[1]
	params.Set("algo", hashName)

	params.Set("digits", strconv.Itoa(k.Digits))

	if k.Method == "totp" {
		params.Set("period", strconv.Itoa(k.Period))
	}

	if k.Method == "hotp" {
		params.Set("counter", strconv.Itoa(k.Counter))
	}

	uri.RawQuery = params.Encode()
	return uri.String()
}

// Parse OTPAUTH URI into Key attributes.
func (k *Key) FromURI(uri string) error {

	u, err := url.ParseRequestURI(uri)
	if err != nil {
		return err
	}

	if u.Scheme != "otpauth" {
		return errors.New("invalid scheme")
	}

	(*k).Method = u.Host

	if u.Path == "" {
		return errors.New("missing label")
	}
	(*k).Label = u.Path[1:len(u.Path)]

	params := u.Query()
	(*k).Secret = params.Get("secret")
	(*k).Issuer = params.Get("issuer")

	// parse out hashing algo; default to sha1
	switch strings.ToUpper(params.Get("algo")) {
	case "SHA256":
		(*k).Algo = sha256.New
	case "SHA512":
		(*k).Algo = sha512.New
	case "MD5":
		(*k).Algo = md5.New
	default:
		(*k).Algo = sha1.New

	}

	digits := params.Get("digits")
	if digits != "" {
		d, err := strconv.Atoi(digits)
		if err != nil {
			return errors.New("digits is non-integer")
		}
		(*k).Digits = d
	} else {
		(*k).Digits = 6
	}

	// totp: try to get a period; else default to 30
	// hotp: try to get a counter
	if u.Host == "totp" {
		period := params.Get("period")
		if period != "" {
			p, err := strconv.Atoi(period)
			if err != nil {
				return errors.New("period is non-integer")
			}
			(*k).Period = p
		} else {
			(*k).Period = 30
		}
	} else if u.Host == "hotp" {
		counter := params.Get("counter")
		if counter != "" {
			c, err := strconv.Atoi(counter)
			if err != nil {
				return errors.New("counter is non-integer")
			}
			(*k).Counter = c
		}
	}

	return nil
}