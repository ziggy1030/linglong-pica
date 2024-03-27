/*
 * SPDX-FileCopyrightText: 2022 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"pkg.deepin.com/linglong/pica/cli"
	"pkg.deepin.com/linglong/pica/cli/command/commands"
	"pkg.deepin.com/linglong/pica/tools/log"
)

// var (
// 	disableDevelop string
// )

func main() {
	log.Logger = log.InitLog()
	defer log.Logger.Sync()

	if err := runPica(); err != nil {
		log.Logger.Errorf("run pica failed: %v", err)
		os.Exit(1)
	}
}

func newPicaCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ll-pica",
		Short: "debian package convert linglong package",
		Long: `Convert the deb to uab. For example:
Simple:
	ll-pica init -c package -w work-dir
	ll-pica convert -c package.yaml -w work-dir
	ll-pica push -i appid -w work-dir
	ll-pica help
		`,
		Version: fmt.Sprint("1.0.2", "test"),
		PostRun: func(cmd *cobra.Command, args []string) {
			cmd.Usage()
		},
	}

	cmd.CompletionOptions.DisableDefaultCmd = true
	cli.SetupRootCommand(cmd)
	commands.AddCommands(cmd)
	return cmd
}

func runPica() error {
	cmd := newPicaCommand()
	return cmd.Execute()
}
