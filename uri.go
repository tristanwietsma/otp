package otp

import (
	_ "bytes"
	_ "text/template"
)

// Defines a secret key per otpauth specifications. See https://code.google.com/p/google-authenticator/wiki/KeyUriFormat for more information.
type KeyUri struct {
	method  string // Defines the method used; must be `totp` or `hotp`.
	label   string // Identifies the account the key is associated with.
	secret  string // Base32 encoded secret key.
	issuer  string // Identifies the service provider the key is associated with.
	algo    string // The hash algorithm used. `SHA1`, `SHA256`, `SHA512`, or `MD5` are valid.
	digits  int    // The length of the code.
	counter int64  // The initial counter value. Applies only to `hotp`.
	period  int64  // The number of second the code is valid for. Applies only to `totp`.
}

/* Returns the string representation of the KeyUri.
func (k KeyUri) String() string {
	markup := "otpauth://{{.method}}/{{.label}}?secret={{.secret}}"

	if k.issuer != nil {
		markup = markup + "&issuer={{.issuer}}"
	}

	if k.algo != nil {

	} else {

	}

	tmpl, _ := template.New("uri").Parse(markup)
	var uri bytes.Buffer
	tmpl.Execute(&uri, k)
	return uri.String()
}*/
