package main

import (
	"context"
	"flag"
	"os"

	"github.com/google/subcommands"
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "") // help  command
	subcommands.Register(&decodeCmd{}, "")              // serve command
	subcommands.Register(&encodeCmd{}, "")              // job   command

	flag.Parse()
	os.Exit(int(subcommands.Execute(context.Background())))
}
