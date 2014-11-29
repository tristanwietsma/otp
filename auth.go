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

// Type to represent <lib>.New function, where lib implements Go's hash library.
type Hash func() hash.Hash

// Returns the current time interval as unix epoch divided by "period".
func GetInterval(period int64) int64 {
	return time.Now().Unix() / period
}

// Returns a one-time password.
// "secret" is a Base32 encoded HMAC key.
// "iv" is the initialization value for the HMAC.
// "hashFunc" is the hashing function to use in the HMAC. See otp.HASHES.
// "digits" is the length of digits to display in the output code.
//
// Example:
//      code, err := GetCode("MFRGGZDFMZTWQ2LK", 1, sha1.New, 6)
func GetCode(secret string, iv int64, hashFunc Hash, digits int) (string, error) {
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}

	msg := bytes.Buffer{}
	_ = binary.Write(&msg, binary.BigEndian, iv)

	mac := hmac.New(hashFunc, key)
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
