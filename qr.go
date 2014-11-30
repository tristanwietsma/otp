package otp

import (
	"code.google.com/p/rsc/qr"
)

func (k Key) QrCode() (*Code, err) {
	return qr.Encode(k.ToURI(), qr.H)
}
