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

type Hash func() hash.Hash

// Returns the current time interval.
func GetInterval(period int64) int64 {
	return time.Now().Unix() / period
}

// Returns the TOTP/HOTP code.
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
