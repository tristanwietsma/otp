package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
)

type listCommand struct{}

func (c listCommand) Name() string {
	return "list"
}

func (c listCommand) Run(args []string) {
	var cfg config
	path := getCfg()
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		fmt.Println(err)
	}
	fmt.Println(cfg)
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
