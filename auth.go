package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"strconv"
	"time"
)

// Returns the current time interval using the Google Authenticator convention of 30 seconds.
func GetInterval() int64 {
	return time.Now().Unix() / 30
}

// Returns the TOTP code using the Google Authenticator convention of SHA1.
func GetCode(secret string, iv int64) string {
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		panic(err)
	}

	msg := bytes.Buffer{}
	err = binary.Write(&msg, binary.BigEndian, iv)
	if err != nil {
		panic(err)
	}

	mac := hmac.New(sha1.New, key)
	mac.Write(msg.Bytes())
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0xF
	truncatedHash := hash[offset : offset+4]

	var code int32
	truncBytes := bytes.NewBuffer(truncatedHash)
	err = binary.Read(truncBytes, binary.BigEndian, &code)
	if err != nil {
		panic(err)
	}

	code = (code & 0x7FFFFFFF) % 1000000
	return strconv.Itoa(int(code))
}
