package otp

import (
	"crypto/sha1"
	"testing"
)

func TestGetInterval(t *testing.T) {
	iv, r := GetInterval(30)
	if iv < 0 {
		t.Error("Time interval is negative.")
	}
	if r < 0 {
		t.Error("Negative time remaining.")
	}
}

func TestGetCode(t *testing.T) {
	code, err := GetCode("MFRGGZDFMZTWQ2LK", 1, sha1.New, 6)
	if err != nil || code != "765705" {
		t.Errorf("Code did not match for first interval:\n%v\n%v", code, err)
	}

	code, err = GetCode("MFRGGZDFMZTWQ2LK", 2, sha1.New, 6)
	if err != nil || code != "816065" {
		t.Errorf("Code did not match for second interval:\n%v\n%v", code, err)
	}
}

func TestBadSecretInGetCode(t *testing.T) {
	code, err := GetCode("abc123", 1, sha1.New, 6)
	if err == nil {
		t.Errorf("Decoding worked for bad base32:\n%v\n%v", code, err)
	}
}

func TestShortDigits(t *testing.T) {
	code, err := GetCode("MFRGGZDFMZTWQ2LK", 19, sha1.New, 6)
	if len(code) != 6 || err != nil {
		t.Errorf("Code length is not 6 digits as expected.\n%v\n%v", code, err)
	}
}
