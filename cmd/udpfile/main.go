package main

import (
	"fmt"
	"os"

	"udpfile/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "udpfile: %v\n", err)
		os.Exit(1)
	}
}
