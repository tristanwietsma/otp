package otp

import (
	"code.google.com/p/rsc/qr"
)

func (k Key) QrCode() (*qr.Code, error) {
	code, err := qr.Encode(k.ToURI(), qr.H)
	return code, err
}
