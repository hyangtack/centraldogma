// Copyright 2017 LINE Corporation
//
// LINE Corporation licenses this file to you under the Apache License,
// version 2.0 (the "License"); you may not use this file except in compliance
// with the License. You may obtain a copy of the License at:
//
//   https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package main

import (
	"os"

	"github.com/line/centraldogma/client/go/cmd"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "Central Dogma"
	app.Usage = "Central Dogma client"
	app.UsageText = "dogma command [arguments]"
	app.HelpName = "dogma"
	app.Version = "0.17.0"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name: "connect, c",
			Usage: "Specifies host or IP address with port to connect to:" +
				"[hostname:port] or [http://hostname:port]",
		},
		cli.StringFlag{
			Name:  "username, u",
			Usage: "Specifies the username to log in as",
		},
		cli.StringFlag{
			Name:  "token, t",
			Usage: "Specifies the token to authenticate",
		},
	}

	app.Commands = cmd.CLICommands()
	app.HideVersion = true
	cli.HelpFlag = cli.BoolFlag{
		Name:  "help, h",
		Usage: "Shows help",
	}
	cli.CommandHelpTemplate = commandHelpTemplate
	app.Run(os.Args)
}

var commandHelpTemplate = `DESCRIPTION:
   {{if .Usage}}{{.Usage}}{{end}}

USAGE:
   {{if .UsageText}}{{.UsageText}}{{else}}{{.HelpName}}{{if .VisibleFlags}} [command options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}{{end}}{{if .Category}}

CATEGORY:
   {{.Category}}{{end}}{{if .VisibleFlags}}

OPTIONS:
   {{range .VisibleFlags}}{{.}}
   {{end}}{{end}}
`
