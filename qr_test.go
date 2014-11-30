package otp

import (
	"crypto/sha1"
	"testing"
)

func TestSmokeQR(t *testing.T) {
	key, _ := NewHOTPKey(
		"label",
		"MFRGGZDFMZTWQ2LK",
		"issuer",
		sha1.New,
		6,
		42,
	)

	if _, err := key.QrCode(); err != nil {
		t.Fail()
	}
}
