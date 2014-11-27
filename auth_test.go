package totp

import "testing"

func TestGetInterval(t *testing.T) {
	iv := GetInterval()
	if iv < 0 {
		t.Fail()
	}
}

func TestGetCode(t *testing.T) {
	// test cases borrowed from the excellent Python project:
	// https://github.com/tadeck/onetimepass
	code := GetCode("MFRGGZDFMZTWQ2LK", 1)
	if code != "765705" {
		t.Fail()
	}

	code = GetCode("MFRGGZDFMZTWQ2LK", 2)
	if code != "816065" {
		t.Fail()
	}
}
