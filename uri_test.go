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
			Method:   "totp",
			Label:    "label",
			Secret32: "MFRGGZDFMZTWQ2LK",
			Issuer:   "issuer",
			Algo:     sha1.New,
			Digits:   6,
			Period:   30,
		},
		U: "otpauth://totp/label?algo=sha1&digits=6&issuer=issuer&period=30&secret=MFRGGZDFMZTWQ2LK",
	},
	CheckPair{
		K: Key{
			Method:   "hotp",
			Label:    "label",
			Secret32: "MFRGGZDFMZTWQ2LK",
			Issuer:   "issuer",
			Algo:     sha1.New,
			Digits:   6,
			Counter:  42,
		},
		U: "otpauth://hotp/label?algo=sha1&counter=42&digits=6&issuer=issuer&secret=MFRGGZDFMZTWQ2LK",
	},
	CheckPair{
		K: Key{
			Method:   "totp",
			Label:    "Example:alice@google.com",
			Secret32: "NAR5XTDD3EQU22YU",
			Issuer:   "Example",
			Algo:     sha1.New,
			Digits:   6,
			Period:   30,
		},
		U: "otpauth://totp/Example:alice@google.com?algo=sha1&digits=6&issuer=Example&period=30&secret=NAR5XTDD3EQU22YU",
	},
}

func TestCheckPairs(t *testing.T) {
	var theKey *Key
	var err error
	for _, p := range Pairs {
		if p.K.Method == "totp" {
			theKey, err = NewTOTPKey(p.K.Label, p.K.Secret32, p.K.Issuer, p.K.Algo, p.K.Digits, p.K.Period)
		} else {
			theKey, err = NewHOTPKey(p.K.Label, p.K.Secret32, p.K.Issuer, p.K.Algo, p.K.Digits, p.K.Counter)
		}
		if err != nil {
			t.Errorf("Failed to build key from %v\n%v", p.K, err)
		}
		uri := theKey.ToURI()
		if uri != p.U {
			t.Errorf("Does not match template:\n%v\n%v", uri, p.U)
		}

		err := (*theKey).FromURI(p.U)
		if err != nil {
			t.Errorf("Unable to parse uri into Key: %v", err)
		}

		if (*theKey).Method != p.K.Method {
			t.Error("Methods don't match")
		}
		if (*theKey).Label != p.K.Label {
			t.Error("Labels don't match")
		}
		if (*theKey).Secret32 != p.K.Secret32 {
			t.Error("Secret32s don't match")
		}
		if (*theKey).Issuer != p.K.Issuer {
			t.Error("Issuers don't match")
		}
		if getFuncName((*theKey).Algo) != getFuncName(p.K.Algo) {
			t.Error("Algos don't match")
		}
		if (*theKey).Digits != p.K.Digits {
			t.Error("Digits don't match")
		}
		if (*theKey).Counter != p.K.Counter {
			t.Error("Counters don't match")
		}
		if (*theKey).Period != p.K.Period {
			t.Error("Periods don't match")
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
		k.Secret32 != "MFRGGZDFMZTWQ2LK" &&
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
	for i := range pairs {
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
