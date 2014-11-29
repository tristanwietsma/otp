package otp

import (
	"reflect"
	"runtime"
)

// http://stackoverflow.com/a/7053871/3582177
func getFuncName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func hashInSlice(a Hash, list []Hash) bool {
	for _, b := range list {
		if getFuncName(b) == getFuncName(a) {
			return true
		}
	}
	return false
}
