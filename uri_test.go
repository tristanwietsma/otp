package otp

import (
	"testing"
)

func TestNewTOTP(t *testing.T) {
	if _, err := NewTOTP(
		"label",
		"MFRGGZDFMZTWQ2LK",
		"issuer",
		"sha1",
		6,
		30,
	); err != nil {
		t.Error("failed to build new totp key")
	}
}

func TestNewHOTP(t *testing.T) {
	if _, err := NewHOTP(
		"label",
		"MFRGGZDFMZTWQ2LK",
		"issuer",
		"sha1",
		6,
		30,
	); err != nil {
		t.Error("failed to build new hotp key")
	}
}

/*uri := key.String()
if uri != "blah" {
	t.Error(uri)
}*/
