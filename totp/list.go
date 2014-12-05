package main

import (
	"fmt"
)

type listCommand struct{}

func (c listCommand) Name() string {
	return "list"
}

func (c listCommand) Run(args []string) {
	fmt.Println("list runs")
}

func (c listCommand) Usage() {
	usage := "    list        list keys"
	fmt.Println(usage)
}

func (c listCommand) Help() {
	help := "\n" + c.Name() + " usage:\n\n    totp " + c.Name() + "\n\n"
	help += "    Lists all keys stored in " + getCfg() + ".\n"
	fmt.Println(help)
}
