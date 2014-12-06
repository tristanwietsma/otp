// Command 2fa is a terminal-based replacement for Google Authenticator
package main

import (
	"flag"
	"fmt"
)

type command interface {
	Name() string
	Run([]string) bool
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
		`2fa is a time-based, one-time password generator.

Usage:

        2fa command [arguments]

The commands are:
`)
	for _, c := range commands {
		c.Usage()
	}

	fmt.Println(
		`
Use "2fa help [command]" for more information about a command.
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
			if cmd.Run(args[1:]) {
				return
			}
			cmd.Help()
			return
		}
	}

	// help
	if args[0] == "help" {
		if flag.NArg() != 2 {
			fmt.Println("\nhelp usage:\n\n    2fa help [command]\n")
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
