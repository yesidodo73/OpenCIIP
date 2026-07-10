package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/yesidodo73/OpenCIIP/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	os.Exit(cli.Execute(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
