package main

import (
	"fmt"
)

type initCommand struct{}

func (c initCommand) Name() string {
	return "init"
}

func (c initCommand) Run(args []string) {
	fmt.Println("init runs")
}

func (c initCommand) Usage() {
	usage := "    init        create the user config"
	fmt.Println(usage)
}

func (c initCommand) Help() {
	help := "\n" + c.Name() + " usage:\n\n    totp " + c.Name() + "\n\n"
	help += "    Creates a configuration file at " + getCfg() + " if one does not already exist.\n"
	fmt.Println(help)
}
