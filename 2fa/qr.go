package main

import (
	"code.google.com/p/rsc/qr"
	"fmt"
	"github.com/GolangDorks/otp"
)

type qrCommand struct{}

func (q qrCommand) Name() string {
	return "qrcodes"
}

func (q qrCommand) Run(args []string) bool {
	cfg := getCfg()

	qrCodes := []*qr.Code{}
	for name := range cfg.Key {
		issuer := cfg.Key[name].Issuer
		secret := cfg.Key[name].Secret

		k, err := otp.NewTOTPKey(name, secret, issuer, otp.Hashes[0], 6, 30)
		if err != nil {
			fmt.Printf("unable to generate key for %s\n", name)
			return false
		}

		qr, err := k.QrCode()
		if err != nil {
			fmt.Printf("unable to generate QR code for %s\n", name)
			return false
		}
		qrCodes = append(qrCodes, qr)
	}

	serve(qrCodes)
	return true
}

func (q qrCommand) Usage() {
	usage := "    qrcodes     start server with qr codes"
	fmt.Println(usage)
}

func (q qrCommand) Help() {
	help := "\n" + q.Name() + " usage:\n\n    totp " + q.Name() + "\n\n"
	help += "    Displays QR codes for all keys stored in " + getCfgPath() + ".\n"
	fmt.Println(help)
}
