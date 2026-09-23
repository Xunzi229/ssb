package main

import (
	"context"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"ssb/config"
	"ssb/dao"
	"ssb/service"
	"time"
)

var app = &cli.App{}

func init() {
	app = &cli.App{
		Commands: []*cli.Command{
			{
				Name:    "gen",
				Aliases: []string{"g"},
				Usage:   "Generate new rsa key",
				Action: func(c *cli.Context) error {
					return service.Generate(context.Background())
				},
			},
			{
				Name:    "backup",
				Aliases: []string{"b"},
				Usage:   "Back up the current SSH key",
				Action: func(c *cli.Context) error {
					name := time.Now().Format(config.BackUpTime)
					if c.NArg() > 0 {
						name = c.Args().Get(0)
					}
					return service.Backup(context.Background(), name)
				},
			},
			{
				Name:    "list",
				Aliases: []string{"l"},
				Usage:   "Show all backups",
				Action: func(c *cli.Context) error {
					service.List(context.Background())
					return nil
				},
			},
			{
				Name:    "switch",
				Aliases: []string{"s"},
				Usage:   "switch backup",
				Action: func(c *cli.Context) error {
					dst := ""
					if c.NArg() > 0 {
						dst = c.Args().Get(0)
					}
					return service.Switch(context.Background(), dst)
				},
			},
			{
				Name:    "export",
				Aliases: []string{"p"},
				Usage:   "Export backup file",
				Action: func(c *cli.Context) error {
					dst := ""
					if c.NArg() > 0 {
						dst = c.Args().Get(0)
					}
					return service.Export(context.Background(), dst)
				},
			},
			{
				Name:    "load",
				Aliases: []string{"load"},
				Usage:   "Import backup file",
				Action: func(c *cli.Context) error {
					zip := ""
					if c.NArg() > 0 {
						zip = c.Args().Get(0)
					}
					return service.Load(context.Background(), zip)
				},
			},
		},
		Name:    "SSB",
		Version: "v0.0.2",
	}

}

func main() {
	defer func() {
		if dao.StopChan != nil {
			dao.StopChan <- true
		}
	}()

	go dao.Run()

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
