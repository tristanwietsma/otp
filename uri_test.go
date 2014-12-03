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

func TestBadURIs(t *testing.T) {
	var BadURIs = []string{
		"abcotpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer",
		"otpauth:totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer",
		"otpauth//totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer",
		"otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=SHA1&digits=X",
		"otpauth://hotp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=SHA1&counter=X",
		"otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&period=X",
	}

	k := Key{}
	for _, u := range BadURIs {
		if err := k.FromURI(u); err == nil {
			t.Errorf("FromURI should have failed: %v", u)
		}
	}
}

func TestParseAlgo(t *testing.T) {
	pairs := []string{
		"otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=SHA1", getFuncName(sha1.New),
		"otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=sha1", getFuncName(sha1.New),
		"otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=SHA256&nonsense=1", getFuncName(sha256.New),
		"otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=sha256", getFuncName(sha256.New),
		"otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=SHA512", getFuncName(sha512.New),
		"otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=sha512", getFuncName(sha512.New),
		"otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=MD5", getFuncName(md5.New),
		"otpauth://totp/label?secret=MFRGGZDFMZTWQ2LK&issuer=theIssuer&algo=md5", getFuncName(md5.New),
	}

	k := Key{}
	for i, _ := range pairs {
		if i%2 == 1 {
			continue
		}
		if err := k.FromURI(pairs[i]); getFuncName(k.Algo) != pairs[i+1] || err != nil {
			t.Errorf("Parse failed: %v", pairs[i])
		}
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
