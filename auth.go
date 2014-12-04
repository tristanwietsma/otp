package otp

import (
	"bytes"
	"crypto/hmac"
	"encoding/base32"
	"encoding/binary"
	"hash"
	"strconv"
	"time"
)

// Hash is a type to represent functions that return a hash.Hash.
type Hash func() hash.Hash

// GetInterval returns the current time interval as unix epoch divided by period.
func GetInterval(period int64) int64 {
	return time.Now().Unix() / period
}

// GetCode returns a one-time password.
// The secret32 parameter is a Base32-encoded HMAC key.
// The iv parameter is the initialization value.
// The h parameter is a hash function to use in the HMAC.
// The digits parameter is the length of returned code.
//
// Example:
//      code, err := GetCode("MFRGGZDFMZTWQ2LK", 1, sha1.New, 6)
func GetCode(secret32 string, iv int64, h Hash, digits int) (string, error) {
	key, err := base32.StdEncoding.DecodeString(secret32)
	if err != nil {
		return "", err
	}

	msg := bytes.Buffer{}
	binary.Write(&msg, binary.BigEndian, iv)

	mac := hmac.New(h, key)
	mac.Write(msg.Bytes())
	digest := mac.Sum(nil)

	offset := digest[len(digest)-1] & 0xF
	trunc := digest[offset : offset+4]

	var code int32
	truncBytes := bytes.NewBuffer(trunc)
	_ = binary.Read(truncBytes, binary.BigEndian, &code)

	code = (code & 0x7FFFFFFF) % 1000000
	stringCode := strconv.Itoa(int(code))
	for len(stringCode) < digits {
		stringCode = "0" + stringCode
	}
	return stringCode, nil
}
