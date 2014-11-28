package totp

import (
	"crypto/sha1"
	"testing"
)

func TestGetInterval(t *testing.T) {
	iv := GetInterval(30)
	if iv < 0 {
		t.Fail()
	}
}

func TestGetCode(t *testing.T) {
	// test cases borrowed from the excellent Python project:
	// https://github.com/tadeck/onetimepass
	code := GetCode("MFRGGZDFMZTWQ2LK", 1, sha1.New, 6)
	if code != "765705" {
		t.Fail()
	}

	code = GetCode("MFRGGZDFMZTWQ2LK", 2, sha1.New, 6)
	if code != "816065" {
		t.Fail()
	}
}
