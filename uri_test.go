package otp

import (
	"testing"
)

func TestNewTOTP(t *testing.T) {
	_, err := NewTOTP(
		"label",
		"MFRGGZDFMZTWQ2LK",
		"issuer",
		"sha1",
		6,
		30,
	)

	if err != nil {
		t.Error("failed to build new totp key")
	}

	/*uri := key.String()
	if uri != "blah" {
		t.Error(uri)
	}*/
}
