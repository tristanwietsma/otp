package main

import (
	"flag"
	"log"
	"os/user"
)

type command interface {
	Name()
	Run([]string)
	Usage()
}

var commands = []*command{
	cmdCalc,
	cmdList,
	cmdInit,
}

func usage() {
	// to do
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
	}

	for _, cmd := range commands {
		if cmd.Name() == args[0] {
			cmd.Run(args[1:])
			return
		}
	}

	usage()
}

func getCfg() string {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	return usr.HomeDir + "/.totp.toml"
}
