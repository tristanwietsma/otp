package otp

import (
	"code.google.com/p/go.crypto/md4"
	"crypto/sha1"
	"testing"
)

func TestkeyError(t *testing.T) {
	err := keyError{
		param: "param",
		msg:   "msg",
	}
	if err.Error() != "KeyError - param - msg" {
		t.Fail()
	}
}

func TestInvalidMethod(t *testing.T) {
	key := Key{
		Method: "crypto!",
	}
	v, _ := key.IsValid()
	if v == true {
		t.Fail()
	}
}

func TestMissingLabel(t *testing.T) {
	key := Key{
		Method: "totp",
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

func TestMissingSecret(t *testing.T) {
	key := Key{
		Method: "totp",
		Label:  "t@w",
	}
	v, _ := key.IsValid()
	if v == true {
		t.Fail()
	}
}

func TestBadSecret(t *testing.T) {
	key := Key{
		Method: "totp",
		Label:  "t@w",
		Secret: "abc123",
	}
	v, _ := key.IsValid()
	if v == true {
		t.Fail()
	}
}

func TestBadIssuer(t *testing.T) {
	key := Key{
		Method: "totp",
		Label:  "t@w",
		Secret: "MFRGGZDFMZTWQ2LK",
		Issuer: "issu/er",
	}
	v, _ := key.IsValid()
	if v == true {
		t.Fail()
	}
}

func TestBadAlgo(t *testing.T) {
	key := Key{
		Method: "totp",
		Label:  "t@w",
		Secret: "MFRGGZDFMZTWQ2LK",
		Issuer: "issuer",
		Algo:   md4.New,
	}
	v, _ := key.IsValid()
	if v == true {
		t.Fail()
	}
}

func TestBadDigits(t *testing.T) {
	key := Key{
		Method: "totp",
		Label:  "t@w",
		Secret: "MFRGGZDFMZTWQ2LK",
		Issuer: "issuer",
		Algo:   sha1.New,
		Digits: 99,
	}
	v, _ := key.IsValid()
	if v == true {
		t.Fail()
	}
}

func TestBadPeriod(t *testing.T) {
	key := Key{
		Method: "totp",
		Label:  "t@w",
		Secret: "MFRGGZDFMZTWQ2LK",
		Issuer: "issuer",
		Algo:   sha1.New,
		Digits: 6,
		Period: -42,
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
		sha1.New,
		6,
		30,
	)

	uri := key.String()
	if uri != "otpauth://totp/label?Secret=MFRGGZDFMZTWQ2LK&Issuer=issuer&Algo=SHA1&Digits=6&Period=30" {
		t.Error(uri)
	}
}

func TestHotpString(t *testing.T) {
	key, _ := NewHotp(
		"label",
		"MFRGGZDFMZTWQ2LK",
		"issuer",
		sha1.New,
		6,
		42,
	)

	uri := key.String()
	if uri != "otpauth://hotp/label?Secret=MFRGGZDFMZTWQ2LK&Issuer=issuer&Algo=SHA1&Digits=6&Counter=42" {
		t.Error(uri)
	}
}

func TestGetHotpCode(t *testing.T) {
	key, _ := NewHotp(
		"label",
		"MFRGGZDFMZTWQ2LK",
		"issuer",
		sha1.New,
		6,
		0,
	)
	code, err := key.GetHotpCode(1)
	if err != nil || code != "765705" {
		t.Error("Code did not match for first interval.")
	}
}

func TestSmokeGetTotpCode(t *testing.T) {
	key, _ := NewTotp(
		"label",
		"MFRGGZDFMZTWQ2LK",
		"issuer",
		sha1.New,
		6,
		30,
	)
	if _, err := key.GetTotpCode(); err != nil {
		t.Fail()
	}
}
