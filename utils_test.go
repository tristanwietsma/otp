package otp

import "testing"

func TestStringInSlice(t *testing.T) {
	if stringInSlice("A", []string{"A", "B"}) != true {
		t.Fail()
	}
}

func TestStringNotInSlice(t *testing.T) {
	if stringInSlice("C", []string{"A", "B"}) == true {
		t.Fail()
	}
}
