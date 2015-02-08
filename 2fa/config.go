package main

import (
	"github.com/BurntSushi/toml"
	"log"
	"os/user"
)

func getCfgPath() string {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	return usr.HomeDir + "/.2fa.toml"
}

func getCfg() *config {
	var cfg config
	path := getCfgPath()
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		log.Fatal(err)
	}
	return &cfg
}
