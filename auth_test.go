package otp

import (
	"crypto/sha1"
	"testing"
)

func TestGetInterval(t *testing.T) {
	iv := GetInterval(30)
	if iv < 0 {
		t.Error("Time interval is negative.")
	}
}

func TestGetCode(t *testing.T) {
	// test cases borrowed from the excellent Python project:
	// https://github.com/tadeck/onetimepass
	code, err := GetCode("MFRGGZDFMZTWQ2LK", 1, sha1.New, 6)
	if err != nil || code != "765705" {
		t.Error("Code did not match for first interval.")
	}

	code, err = GetCode("MFRGGZDFMZTWQ2LK", 2, sha1.New, 6)
	if err != nil || code != "816065" {
		t.Error("Code did not match for second interval.")
	}
}

func TestBadSecretInGetCode(t *testing.T) {
	_, err := GetCode("abc123", 1, sha1.New, 6)
	if err == nil {
		t.Error("Decoding worked for bad base32.")
	}
}

func TestShortDigits(t *testing.T) {
	code, _ := GetCode("MFRGGZDFMZTWQ2LK", 19, sha1.New, 6)
	if len(code) != 6 {
		t.Fail()
	}
}
