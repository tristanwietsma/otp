package otp

import (
	"github.com/tristanwietsma/rsc/qr"
)

// QrCode returns the qr.Code representation of the otpauth URI.
func (k Key) QrCode() (*qr.Code, error) {
	code, err := qr.Encode(k.ToURI(), qr.H)
	return code, err
}
