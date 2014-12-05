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
