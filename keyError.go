package otp

import "fmt"

// Custom error type for Key related errors. Generally refers to validation errors.
type KeyError struct {
	param string
	msg   string
}

// Renders the error string.
func (e KeyError) Error() string {
	return fmt.Sprintf("KeyError - %v - %v", e.param, e.msg)
}
