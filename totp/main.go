package main

import (
	"flag"
	"fmt"
	"log"
	"os/user"
)

type command interface {
	Name() string
	Run([]string)
	Usage()
	Help()
}

var commands = []command{
	&calcCommand{},
	&listCommand{},
	&initCommand{},
}

func usage() {
	fmt.Println(
		`totp is a time-based, one-time password generator.

Usage:

        totp command [arguments]

The commands are:
`)
	for _, c := range commands {
		c.Usage()
	}

	fmt.Println(
		`
Use "totp help [command]" for more information about a command.
`)
}

func main() {

	flag.Usage = usage
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
		return
	}

	args := flag.Args()

	// search commands
	for _, cmd := range commands {
		if cmd.Name() == args[0] {
			cmd.Run(args[1:])
			return
		}
	}

	// help
	if args[0] == "help" {
		if flag.NArg() != 2 {
			fmt.Println("\nhelp usage:\n\n    totp help [command]\n")
			return
		}
		for _, cmd := range commands {
			if args[1] == cmd.Name() {
				cmd.Help()
				return
			}
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
