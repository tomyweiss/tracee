package main

import (
	"errors"
	"log"
	"os"
	"time"

	"github.com/aquasecurity/tracee/tracee-rules/logic"
	"github.com/aquasecurity/tracee/tracee-rules/model"

	cli "github.com/urfave/cli/v2"
)

type Clock interface {
	Now() time.Time
}

type realClock struct {
}

func (realClock) Now() time.Time {
	return time.Now()
}

func main() {
	app := &cli.App{
		Name:  "tracee-rules",
		Usage: "A rule engine for Runtime Security",
		Action: func(c *cli.Context) error {

			if c.NumFlags() == 0 {
				cli.ShowAppHelp(c)
				return errors.New("no flags specified")
			}

			config := model.RulesConfig{
				RulesDir:           c.String("rules-dir"),
				Rules:              c.StringSlice("rules"),
				InputMethods:       c.StringSlice("input-tracee"),
				Webhook:            c.String("webhook"),
				WebhookTemplate:    c.String("webhook-template"),
				WebhookContentType: c.String("webhook-content-type"),
				OutputTemplate:     c.String("output-template"),
				ListRules:          c.Bool("list"),
			}

			return logic.InitTraceeRules(config)
		},
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:  "rules",
				Usage: "select which rules to load. Specify multiple rules by repeating this flag. Use --list for rules to select from",
			},
			&cli.StringFlag{
				Name:  "rules-dir",
				Usage: "directory where to search for rules in OPA (.rego) or Go plugin (.so) formats",
			},
			&cli.BoolFlag{
				Name:  "list",
				Usage: "print all available rules",
			},
			&cli.StringFlag{
				Name:  "webhook",
				Usage: "HTTP endpoint to call for every match",
			},
			&cli.StringFlag{
				Name:  "webhook-template",
				Usage: "path to a gotemplate for formatting webhook output",
			},
			&cli.StringFlag{
				Name:  "webhook-content-type",
				Usage: "content type of the template in use. Recommended if using --webhook-template",
			},
			&cli.StringSliceFlag{
				Name:  "input-tracee",
				Usage: "configure tracee-ebpf as input source. see '--input-tracee help' for more info",
			},
			&cli.StringFlag{
				Name:  "output-template",
				Usage: "configure output format via templates. Usage: --output-template=path/to/my.tmpl",
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
