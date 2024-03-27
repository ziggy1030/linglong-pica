package init

import (
	"encoding/json"
	"os"

	"github.com/spf13/cobra"
	"pkg.deepin.com/linglong/pica/cli/comm"
	"pkg.deepin.com/linglong/pica/cli/config"
	"pkg.deepin.com/linglong/pica/cli/deb"
	"pkg.deepin.com/linglong/pica/tools/fs"
	"pkg.deepin.com/linglong/pica/tools/log"
)

type initOptions struct {
	comm.Options
	getType     string
	packageId   string
	packageName string
	config.Config
}

func NewInitCommand() *cobra.Command {
	var options initOptions
	cmd := &cobra.Command{
		Use:   "init [ARG...]",
		Short: "init config template",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(&options)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&options.Options.Config, "config", "c", "", "config file")
	flags.StringVarP(&options.Workdir, "workdir", "w", "", "work directory")
	flags.StringVarP(&options.Id, "id", "i", "", "runtime id")
	flags.StringVarP(&options.Version, "version", "v", "", "runtime version")
	flags.StringVarP(&options.Source, "source", "s", "", "runtime source")
	flags.StringVar(&options.DistroVersion, "dv", "", "distribution Version")
	flags.StringVarP(&options.Arch, "arch", "a", "", "runtime arch")
	flags.StringVarP(&options.getType, "type", "t", "", "get type")
	flags.StringVar(&options.packageId, "pi", "", "package id")
	flags.StringVar(&options.packageName, "pn", "", "package name")
	return cmd
}

func runInit(options *initOptions) error {
	options.Workdir = comm.WorkPath(options.Workdir)
	configFilePath := comm.ConfigFilePath(options.Workdir, options.Options.Config)

	comm.InitWorkDir(options.Workdir)
	// 创建工作目录
	fs.CreateDir(options.Workdir)
	// 创建 ~/.pica 目录
	fs.CreateDir(comm.PicaConfigPath())

	packConf := config.NewPackConfig()
	assign := func(config *string, option string) {
		if option != "" {
			*config = option
		}
	}

	if ret, _ := fs.CheckFileExits(comm.PicaConfigJsonPath()); !ret {
		log.Logger.Infof("%s can not found", comm.PicaConfigJsonPath())
	} else {
		log.Logger.Infof("load %s config", comm.PicaConfigJsonPath())
		picaConfigFd, err := os.ReadFile(comm.PicaConfigJsonPath())
		if err != nil {
			log.Logger.Errorf("load  %s error: %v", configFilePath, err)
			return err
		} else {
			err = json.Unmarshal([]byte(picaConfigFd), &packConf.Runtime)
			if err != nil {
				log.Logger.Errorf("unmarshal error: %s", err)
				return err
			}
		}
	}

	if options.Id != "" || options.Version != "" || options.Source != "" || options.DistroVersion != "" || options.Arch != "" {
		assign(&packConf.Runtime.Config.Id, options.Id)
		assign(&packConf.Runtime.Config.Version, options.Version)
		assign(&packConf.Runtime.Config.Source, options.Source)
		assign(&packConf.Runtime.Config.DistroVersion, options.DistroVersion)
		assign(&packConf.Runtime.Config.Arch, options.Arch)
		packConf.Runtime.Config.SaveOrUpdateConfigJson(comm.PicaConfigJsonPath())
	}

	if options.packageId != "" && options.packageName != "" && options.getType != "" {
		packConf.File.Deb = []deb.Deb{
			{
				Type: options.getType,
				Id:   options.packageId,
				Name: options.packageName,
			},
		}
	}

	packConf.CreatePackConfigYaml(configFilePath)
	return nil
}
