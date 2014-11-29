package otp

import (
	"crypto/sha1"
	"testing"
)

func TestNewTOTPKey(t *testing.T) {
	if _, err := NewTOTPKey(
		"label",
		"MFRGGZDFMZTWQ2LK",
		"issuer",
		sha1.New,
		6,
		30,
	); err != nil {
		t.Errorf("failed to build new totp key:\n%v", err)
	}
}

func TestNewBadTotp(t *testing.T) {
	if _, err := NewTOTPKey(
		"label",
		"MifdasfsfdsfFRGGZDFMZTWQ2LK",
		"issuer",
		sha1.New,
		6,
		30,
	); err == nil {
		t.Fail()
	}
}

func TestNewBadHotp(t *testing.T) {
	if _, err := NewHOTPKey(
		"label",
		"MFRfadfdssdGGZDFMZTWQ2LK",
		"issuer",
		sha1.New,
		6,
		30,
	); err != nil {
		t.Fail()
	}
}

func TestNewHOTPKey(t *testing.T) {
	if _, err := NewHOTPKey(
		"label",
		"MFRGGZDFMZTWQ2LK",
		"issuer",
		sha1.New,
		6,
		30,
	); err != nil {
		t.Error("failed to build new hotp key")
	}
}
