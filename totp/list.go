package main

import (
	"fmt"
)

type listCommand struct{}

func (c listCommand) Name() string {
	return "list"
}

func (c listCommand) Run(args []string) bool {
	cfg := getCfg()
	fmt.Println("Label\tIssuer")

	output := ""
	line := ""
	n := 0
	for label, k := range cfg.Key {
		line = fmt.Sprintf("%v\t%v\n", label, k.Issuer)
		m := len(line)
		if m > n {
			n = m
		}
		output += line
	}

	dash := "---"
	for len(dash) < n+4 {
		dash += "-"
	}
	fmt.Println(dash)

	fmt.Print(output)
	return true
}

func (c listCommand) Usage() {
	usage := "    list        list keys"
	fmt.Println(usage)
}

func (c listCommand) Help() {
	help := "\n" + c.Name() + " usage:\n\n    totp " + c.Name() + "\n\n"
	help += "    Lists all keys stored in " + getCfgPath() + ".\n"
	fmt.Println(help)
}
