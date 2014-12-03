package otp

import (
	"crypto/sha1"
	"testing"
)

func TestKeyError(t *testing.T) {
	err := KeyError{
		param: "param",
		msg:   "msg",
	}
	if err.Error() != "KeyError - param - msg" {
		t.Fail()
	}
}

func TestKeyGetCode(t *testing.T) {
	hkey, _ := NewHOTPKey(
		"label",
		"MFRGGZDFMZTWQ2LK",
		"issuer",
		sha1.New,
		6,
		0,
	)
	code, err := hkey.GetCode(1)
	if err != nil || code != "765705" {
		t.Error("Code did not match for first interval.")
	}

	// this is just smoke
	tkey, _ := NewTOTPKey(
		"label",
		"MFRGGZDFMZTWQ2LK",
		"issuer",
		sha1.New,
		6,
		30,
	)
	if _, err := tkey.GetCode(1); err != nil {
		t.Fail()
	}
}
