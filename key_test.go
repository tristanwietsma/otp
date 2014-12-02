package otp

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

func TestKeyError(t *testing.T) {
	err := KeyError{
		param: "param",
		msg:   "msg",
	}
	if err.Error() != "KeyError - param - msg" {
		t.Fail()
	}
}

func TestTOTPString(t *testing.T) {
	key, _ := NewTOTPKey(
		"label",
		"MFRGGZDFMZTWQ2LK",
		"issuer",
		sha1.New,
		6,
		30,
	)

	uri := key.ToURI()
	if uri != "otpauth://totp/label?algo=sha1&digits=6&issuer=issuer&period=30&secret=MFRGGZDFMZTWQ2LK" {
		t.Error(uri)
	}
}

func TestHOTPString(t *testing.T) {
	key, _ := NewHOTPKey(
		"label",
		"MFRGGZDFMZTWQ2LK",
		"issuer",
		sha1.New,
		6,
		42,
	)

	uri := key.ToURI()
	if uri != "otpauth://hotp/label?algo=sha1&counter=42&digits=6&issuer=issuer&secret=MFRGGZDFMZTWQ2LK" {
		t.Error(uri)
	}
}

func TestKeyGetCode(t *testing.T) {
	hkey, _ := NewHOTPKey(
		"label",
		"MFRGGZDFMZTWQ2LK",
		"issuer",
		sha1.New,
		6,
		0,
	)
	code, err := hkey.GetCode(1)
	if err != nil || code != "765705" {
		t.Error("Code did not match for first interval.")
	}

	// this is just smoke
	tkey, _ := NewTOTPKey(
		"label",
		"MFRGGZDFMZTWQ2LK",
		"issuer",
		sha1.New,
		6,
		30,
	)
	if _, err := tkey.GetCode(1); err != nil {
		t.Fail()
	}
}

func TestFromUri(t *testing.T) {
	k := Key{}
	uri := "otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer"
	if err := k.FromURI(uri); err != nil {
		t.Errorf("Parse URI failed:\n%v", err)
	}

	if k.Method != "totp" &&
		k.Label != "label" &&
		k.Secret != "MFRGGZDFMZTWQ2LK" &&
		k.Issuer != "theIssuer" &&
		getFuncName(k.Algo) != getFuncName(sha1.New) &&
		k.Digits == 6 &&
		k.Period == 30 {
		t.Errorf("Parse failed: %v", k)
	}
}

func TestParseBadScheme(t *testing.T) {
	k := Key{}
	uri := "abcotpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer"
	if err := k.FromURI(uri); err == nil {
		t.Errorf("Parse URI should have failed: %v", k)
	}
}

func TestParseBadUri(t *testing.T) {
	k := Key{}
	uri := "otpauth:totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer"
	if err := k.FromURI(uri); err == nil {
		t.Errorf("Parse URI should have failed: %v", k)
	}

	uri = "otpauth//totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer"
	if err := k.FromURI(uri); err == nil {
		t.Errorf("Parse URI should have failed: %v", k)
	}

	uri = "otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=SHA1&digits=X"
	if err := k.FromURI(uri); err == nil {
		t.Errorf("Parse URI should have failed: %v", k)
	}

	uri = "otpauth://hotp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=SHA1&counter=X"
	if err := k.FromURI(uri); err == nil {
		t.Errorf("Parse URI should have failed: %v", k)
	}

}

func TestBadDigitsInURI(t *testing.T) {
	k := Key{}
	uri := "otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&period=X"
	if err := k.FromURI(uri); err == nil {
		t.Errorf("Parse URI should have failed: %v", k)
	}
}

func TestParseAlgo(t *testing.T) {
	k := Key{}

	// SHA1
	uri := "otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=SHA1"
	if err := k.FromURI(uri); getFuncName(k.Algo) != getFuncName(sha1.New) && err != nil {
		t.Errorf("Parse URI should have parse SHA1\n%v", err)
	}

	// SHA256
	uri = "otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=SHA256&nonsense=1"
	if err := k.FromURI(uri); getFuncName(k.Algo) != getFuncName(sha256.New) && err != nil {
		t.Errorf("Parse URI should have parse SHA256\n%v", err)
	}

	// SHA512
	uri = "otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=SHA512"
	if err := k.FromURI(uri); getFuncName(k.Algo) != getFuncName(sha512.New) && err != nil {
		t.Errorf("Parse URI should have parse SHA512\n%v", err)
	}

	// MD5
	uri = "otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=MD5"
	if err := k.FromURI(uri); getFuncName(k.Algo) != getFuncName(md5.New) && err != nil {
		t.Errorf("Parse URI should have parse MD5\n%v", err)
	}

	// sha1
	uri = "otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=sha1"
	if err := k.FromURI(uri); getFuncName(k.Algo) != getFuncName(sha1.New) && err != nil {
		t.Errorf("Parse URI should have parse SHA1\n%v", err)
	}

	// sha256
	uri = "otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=sha256&nonsense=1"
	if err := k.FromURI(uri); getFuncName(k.Algo) != getFuncName(sha256.New) && err != nil {
		t.Errorf("Parse URI should have parse SHA256\n%v", err)
	}

	// sha512
	uri = "otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=sha512"
	if err := k.FromURI(uri); getFuncName(k.Algo) != getFuncName(sha512.New) && err != nil {
		t.Errorf("Parse URI should have parse SHA512\n%v", err)
	}

	// md5
	uri = "otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=md5"
	if err := k.FromURI(uri); getFuncName(k.Algo) != getFuncName(md5.New) && err != nil {
		t.Errorf("Parse URI should have parse MD5\n%v", err)
	}

}

func TestParseDigits(t *testing.T) {
	k := Key{}

	uri := "otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&digits=8"
	if err := k.FromURI(uri); err != nil && k.Digits != 8 {
		t.Errorf("Didn't parse digits correctly\n%v", err)
	}

	uri = "otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&digits=6"
	if err := k.FromURI(uri); err != nil && k.Digits != 6 {
		t.Errorf("Didn't parse digits correctly\n%v", err)
	}
}

func TestParsePeriod(t *testing.T) {
	k := Key{}
	uri := "otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&period=42"
	if err := k.FromURI(uri); err != nil && k.Period != 42 {
		t.Errorf("Didn't parse period correctly\n%v", err)
	}

	uri = "otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK"
	if err := k.FromURI(uri); err != nil && k.Period != 30 {
		t.Errorf("Didn't parse period correctly\n%v", err)
	}

}

func TestParseCounter(t *testing.T) {
	k := Key{}
	uri := "otpauth://hotp/label?secret=MFRGGZDFMZTWQ2LK&counter=42"
	if err := k.FromURI(uri); err != nil && k.Counter != 42 {
		t.Errorf("Didn't parse period correctly\n%v", err)
	}

	uri = "otpauth://hotp/label?secret=MFRGGZDFMZTWQ2LK"
	if err := k.FromURI(uri); err != nil && k.Counter != 0 {
		t.Errorf("Didn't parse period correctly\n%v", err)
	}

}
