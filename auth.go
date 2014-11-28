package totp

import (
	"bytes"
	"crypto/hmac"
	"encoding/base32"
	"encoding/binary"
	"hash"
	"strconv"
	"time"
)

type hashFunc func() hash.Hash

// Returns the current time interval.
func GetInterval(period int64) int64 {
	return time.Now().Unix() / period
}

// Returns the TOTP/HOTP code.
func GetCode(secret string, iv int64, hasher hashFunc, digits int) (string, error) {
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}

	msg := bytes.Buffer{}
	err = binary.Write(&msg, binary.BigEndian, iv)
	if err != nil {
		return "", err
	}

	mac := hmac.New(hasher, key)
	mac.Write(msg.Bytes())
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0xF
	truncatedHash := hash[offset : offset+4]

	var code int32
	truncBytes := bytes.NewBuffer(truncatedHash)
	err = binary.Read(truncBytes, binary.BigEndian, &code)
	if err != nil {
		return "", err
	}

	code = (code & 0x7FFFFFFF) % 1000000
	stringCode := strconv.Itoa(int(code))
	for len(stringCode) < digits {
		stringCode = "0" + stringCode
	}
	return stringCode, nil
}
