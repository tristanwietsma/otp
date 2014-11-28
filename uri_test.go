package otp

import (
	"testing"
)

func TestNewTotp(t *testing.T) {
	if _, err := NewTotp(
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

func TestNewHotp(t *testing.T) {
	if _, err := NewHotp(
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

func TestTotpString(t *testing.T) {
	key, _ := NewTotp(
		"label",
		"MFRGGZDFMZTWQ2LK",
		"issuer",
		"sha1",
		6,
		30,
	)

	uri := key.String()
	if uri != "otpauth://totp/label?Secret=MFRGGZDFMZTWQ2LK&Issuer=issuer&Algo=SHA1&Digits=6&Period=30" {
		t.Error(uri)
	}
}
