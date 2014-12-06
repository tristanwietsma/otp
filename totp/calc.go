package main

import (
	"fmt"
	"github.com/tristanwietsma/otp"
)

func getCode(secret string) (string, rem) {
	iv, rem := otp.GetInterval(30)
	code, err := otp.GetCode(secret, iv, otp.Hashes[0], 6)
	if err != nil {
		return "calculation failed"
	}
	return code, rem
}

type calcCommand struct{}

func (c calcCommand) Name() string {
	return "calc"
}

func (c calcCommand) Run(args []string) bool {
	if len(args) != 1 {
		return false
	}
	cfg := getCfg()
	k, ok := cfg.Key[args[0]]
	if !ok {
		return false
	}
	code, rem := getCode(k.Secret)
	fmt.Printf("%v (%v seconds)\n", code, rem)
	return true
}

func (c calcCommand) Usage() {
	usage := "    calc        calculate a one-time password"
	fmt.Println(usage)
}

func (c calcCommand) Help() {
	help := "\n" + c.Name() + " usage:\n\n    totp " + c.Name() + " label\n\n"
	help += "    The label is associated with a key and defined in " + getCfgPath() + ".\n"
	fmt.Println(help)
}
