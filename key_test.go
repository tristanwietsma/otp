package otp

import (
	"testing"
)

func TestInvalidMethod(t *testing.T) {
	key := Key{
		Method: "crypto!",
	}
	v, _ := key.IsValid()
	if v == true {
		t.Fail()
	}
}

func TestInvalidLabel(t *testing.T) {
	key := Key{
		Method: "totp",
		Label:  "t/w",
	}
	v, _ := key.IsValid()
	if v == true {
		t.Fail()
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
