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

func TestNewBadTotp(t *testing.T) {
	if _, err := NewTotp(
		"label",
		"MifdasfsfdsfFRGGZDFMZTWQ2LK",
		"issuer",
		"sha1",
		6,
		30,
	); err == nil {
		t.Fail()
	}
}

func TestNewBadHotp(t *testing.T) {
	if _, err := NewHotp(
		"label",
		"MFRfadfdssdGGZDFMZTWQ2LK",
		"issuer",
		"sha1",
		6,
		30,
	); err != nil {
		t.Fail()
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
