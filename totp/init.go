package main

import (
	"fmt"
	"os"
)

type initCommand struct{}

func (c initCommand) Name() string {
	return "init"
}

func (c initCommand) Run(args []string) {
	path := getCfg()
	if _, err := os.Open(path); err != nil {
		f, _ := os.Create(path)
		f.WriteString(
			`# totp configuration
#
# Example:
#
# [key]
# label = "descriptive label for key"
# secret = Base32 encoded secret key
`)
	}
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
