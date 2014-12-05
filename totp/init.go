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
