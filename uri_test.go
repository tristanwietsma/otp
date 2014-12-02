package otp

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

type CheckPair struct {
	K Key
	U string
}

var Pairs = []CheckPair{
	CheckPair{
		K: Key{
			Method: "totp",
			Label:  "label",
			Secret: "MFRGGZDFMZTWQ2LK",
			Issuer: "issuer",
			Algo:   sha1.New,
			Digits: 6,
			Period: 30,
		},
		U: "otpauth://totp/label?algo=sha1&digits=6&issuer=issuer&period=30&secret=MFRGGZDFMZTWQ2LK",
	},
	CheckPair{
		K: Key{
			Method:  "hotp",
			Label:   "label",
			Secret:  "MFRGGZDFMZTWQ2LK",
			Issuer:  "issuer",
			Algo:    sha1.New,
			Digits:  6,
			Counter: 42,
		},
		U: "otpauth://hotp/label?algo=sha1&counter=42&digits=6&issuer=issuer&secret=MFRGGZDFMZTWQ2LK",
	},
}

func TestCheckPairs(t *testing.T) {
	var theKey *Key
	var err error
	for _, p := range Pairs {
		if p.K.Method == "totp" {
			theKey, err = NewTOTPKey(p.K.Label, p.K.Secret, p.K.Issuer, p.K.Algo, p.K.Digits, p.K.Period)
		} else {
			theKey, err = NewHOTPKey(p.K.Label, p.K.Secret, p.K.Issuer, p.K.Algo, p.K.Digits, p.K.Counter)
		}
		if err != nil {
			t.Errorf("Failed to build key from %v", p.K)
		}
		uri := theKey.ToURI()
		if uri != p.U {
			t.Errorf("Does not match template: %v", p.U)
		}
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

var BadURIs = []string{
	"abcotpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer",
	"otpauth:totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer",
	"otpauth//totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer",
	"otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=SHA1&digits=X",
	"otpauth://hotp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=SHA1&counter=X",
	"otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&period=X",
}

func TestBadURIs(t *testing.T) {
	k := Key{}
	for _, u := range BadURIs {
		if err := k.FromURI(u); err == nil {
			t.Errorf("FromURI should have failed: %v", u)
		}
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
