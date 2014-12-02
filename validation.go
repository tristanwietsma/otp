package otp

import (
	"encoding/base32"
)

func (k Key) hasValidMethod() error {
	if !stringInSlice(k.Method, METHODS) {
		return KeyError{"Method", "Invalid value"}
	}
	return nil
}

func (k Key) hasValidLabel() error {
	if len(k.Label) == 0 {
		return KeyError{"Label", "Missing value"}
	}
	return nil
}

func (k Key) hasValidSecret() error {
	if len(k.Secret) == 0 {
		return KeyError{"Secret", "Missing value"}
	}

	if _, err := base32.StdEncoding.DecodeString(k.Secret); err != nil {
		return KeyError{"Secret", "Invalid Base32"}
	}

	return nil
}

func (k Key) hasValidAlgo() error {
	if !hashInSlice(k.Algo, HASHES) {
		return KeyError{"Algo", "Invalid hashing algorithm"}
	}
	return nil
}

func (k Key) hasValidDigits() error {
	if !(k.Digits == 6 || k.Digits == 8) {
		return KeyError{"Digits", "Not equal to 6 or 8"}
	}
	return nil
}

func (k Key) hasValidPeriod() error {
	if k.Method == "totp" && k.Period < 1 {
		return KeyError{"Period", "Negative value"}
	}
	return nil
}

func (k Key) Validate() error {

	// check method
	if err := k.hasValidMethod(); err != nil {
		return err
	}

	//check label
	if err := k.hasValidLabel(); err != nil {
		return err
	}

	// check secret
	if err := k.hasValidSecret(); err != nil {
		return err
	}

	// check algo
	if err := k.hasValidAlgo(); err != nil {
		return err
	}

	// check digits
	if err := k.hasValidDigits(); err != nil {
		return err
	}

	// check period
	if err := k.hasValidPeriod(); err != nil {
		return err
	}

	return nil
}
