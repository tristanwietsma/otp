package otp

import (
	"code.google.com/p/go.crypto/md4"
	"crypto/sha1"
	"testing"
)

var BadKeys = []Key{
	Key{
		Method: "crypto!",
	},
	Key{
		Method: "totp",
	},
	Key{
		Method: "totp",
		Label:  "t@w",
	},
	Key{
		Method: "totp",
		Label:  "t@w",
		Secret: "abc123",
	},
	Key{
		Method: "totp",
		Label:  "t@w",
		Secret: "MFRGGZDFMZTWQ2LK",
		Issuer: "issuer",
		Algo:   md4.New,
	},
	Key{
		Method: "totp",
		Label:  "t@w",
		Secret: "MFRGGZDFMZTWQ2LK",
		Issuer: "issuer",
		Algo:   sha1.New,
		Digits: 99,
	},
	Key{
		Method: "totp",
		Label:  "t@w",
		Secret: "MFRGGZDFMZTWQ2LK",
		Issuer: "issuer",
		Algo:   sha1.New,
		Digits: 6,
		Period: -42,
	},
}

func TestBadKeys(t *testing.T) {
	for _, k := range BadKeys {
		if err := k.Validate(); err == nil {
			t.Errorf("Bad Key didn't produce error on Validate(): %v", k)
		}
	}
}
