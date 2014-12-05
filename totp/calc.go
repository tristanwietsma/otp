package main

import (
	"fmt"
)

type calcCommand struct{}

func (c calcCommand) Name() string {
	return "calc"
}

func (c calcCommand) Run(args []string) {
	fmt.Println("calc runs")
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
