package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	cli "github.com/jawher/mow.cli"
)

func main() {
	// Setup signal handling to print stats on exit
	setupSignalHandling()

	app := cli.App("simple http server", "Serve files over HTTP")

	port := app.String(cli.StringOpt{
		Name:   "p port",
		Value:  "8080",
		Desc:   "Port to listen on",
		EnvVar: "PORT",
	})

	ip := app.String(cli.StringOpt{
		Name:   "i ip",
		Value:  "0.0.0.0",
		Desc:   "IP address to bind to (default is all interfaces)",
		EnvVar: "IP",
	})

	showHidden := app.Bool(cli.BoolOpt{
		Name:   "show-hidden",
		Value:  false,
		Desc:   "Show files and directories starting with a dot (.) (hidden files are hidden by default)",
	})

	files := app.Strings(cli.StringsArg{
		Name: "FILES",
		Desc: "Files or folders to serve",
	})

	app.Action = func() {
		if len(*files) == 0 {
			log.Fatal("Error: You must specify at least one file or folder to serve.")
		}
		serveFiles(*files, *ip, *port, *showHidden)
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func setupSignalHandling() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		printStats()
		os.Exit(0)
	}()
}
