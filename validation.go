package otp

import (
	"encoding/base32"
	"errors"
)

func (k Key) hasValidMethod() error {
	if !stringInSlice(k.Method, methods) {
		return errors.New("Invalid method value")
	}
	return nil
}

func (k Key) hasValidLabel() error {
	if len(k.Label) == 0 {
		return errors.New("Missing value for label")
	}
	return nil
}

func (k Key) hasValidSecret32() error {
	if len(k.Secret32) == 0 {
		return errors.New("Missing value for secret")
	}

	if _, err := base32.StdEncoding.DecodeString(k.Secret32); err != nil {
		return errors.New("Invalid Base32 value for secret")
	}

	return nil
}

func (k Key) hasValidAlgo() error {
	if !hashInSlice(k.Algo, Hashes) {
		return errors.New("Invalid hashing algorithm")
	}
	return nil
}

func (k Key) hasValidDigits() error {
	if !(k.Digits == 6 || k.Digits == 8) {
		return errors.New("Digit is not equal to 6 or 8")
	}
	return nil
}

func (k Key) hasValidPeriod() error {
	if k.Method == "totp" && k.Period < 1 {
		return errors.New("Period can not have a non-positive value")
	}
	return nil
}

// Validate checks if the key parameters conform to the specification.
// In invalid, an error is returns.
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
	if err := k.hasValidSecret32(); err != nil {
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
