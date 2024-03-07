package convert

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"pkg.deepin.com/linglong/pica/cli/comm"
	"pkg.deepin.com/linglong/pica/cli/config"
	"pkg.deepin.com/linglong/pica/cli/deb"
	"pkg.deepin.com/linglong/pica/cli/linglong"
	"pkg.deepin.com/linglong/pica/tools/fs"
	"pkg.deepin.com/linglong/pica/tools/log"
)

type convertOptions struct {
	comm.Options
}

func NewConvertCommand() *cobra.Command {
	var options convertOptions
	cmd := &cobra.Command{
		Use:   "convert [ARG...]",
		Short: "Convert deb to uab",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConvert(&options)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&options.Config, "config", "c", "", "config file")
	flags.StringVarP(&options.Workdir, "workdir", "w", "", "work directory")
	return cmd
}

func runConvert(options *convertOptions) error {
	options.Workdir = comm.WorkPath(options.Workdir)
	configFilePath := comm.ConfigFilePath(options.Workdir, options.Config)
	// 检查配置文件
	if ret, _ := fs.CheckFileExits(configFilePath); !ret {
		log.Logger.Fatalf("%s file is not found: %s", options.Config, configFilePath)
	}

	if strings.HasSuffix(options.Config, ".deb") {
		packConf := config.NewPackConfig()
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
		if ret, msg, err := comm.ExecAndWait(10, "apt-cache", "show", configFilePath); err != nil {
			log.Logger.Warnf("msg: %+v err:%+v, out: %+v", msg, err, ret)
		} else {
			var d deb.Deb
			log.Logger.Debugf("ret: %+v", ret)
			// apt-cache show Unmarshal
			err = yaml.Unmarshal([]byte(ret), &d)
			if err != nil {
				log.Logger.Warnf("apt-cache show unmarshal error: %s", err)
			}
			packConf.File.Deb = []deb.Deb{
				{
					Type: "repo",
					Id:   d.Package,
					Name: d.Package,
				},
			}
			configFilePath = comm.ConfigFilePath(options.Workdir, "")
			packConf.CreatePackConfigYaml(configFilePath)
		}
	}

	log.Logger.Infof("load %s config", configFilePath)
	packConfigFd, err := os.ReadFile(configFilePath)
	if err != nil {
		log.Logger.Fatalf("load  %s error: %v", configFilePath, err)
	}

	packConfig := config.NewPackConfig()
	if err = yaml.Unmarshal(packConfigFd, packConfig); err != nil {
		log.Logger.Fatalf("unmarshal %s error: %v", configFilePath, err)
	}

	for idx := range packConfig.File.Deb {
		appPath := filepath.Join(comm.BuildPackPath(options.Workdir), packConfig.File.Deb[idx].Id, packConfig.Runtime.Arch)
		fs.CreateDir(appPath)
		// 如果 Ref 为空，type 为 repo, 那么先使用 aptly 获取 url 链接， 如果没有就使用 apt download 获取 url 链接，
		// 另外的如果 type 为 local 直接将 deb 包下载到工作目录
		if packConfig.File.Deb[idx].Ref == "" {
			packConfig.File.Deb[idx].Ref = deb.GetPackageUrl(packConfig.File.Deb[idx].Name, packConfig.File.Deb[idx].Id, packConfig.Runtime.Source, packConfig.Runtime.DistroVersion, packConfig.Runtime.Arch)

			// 针对 Type 为 local, 但是没有提供本地路径先通过 apt download 下载 deb 包
			if packConfig.File.Deb[idx].Type == "local" {
				// FetchDebFile 类型是根据，Type 类型调用的，类型为 repo 才会调用 apt download 方法
				packConfig.File.Deb[idx].Type = "repo"
				packConfig.File.Deb[idx].Path = filepath.Join(appPath, filepath.Base(packConfig.File.Deb[idx].Ref))
				packConfig.File.Deb[idx].FetchDebFile(packConfig.File.Deb[idx].Path)
				packConfig.File.Deb[idx].Type = "local"
			}
		}

		// fetch deb file
		if len(packConfig.File.Deb[idx].Ref) > 0 {
			packConfig.File.Deb[idx].Path = filepath.Join(appPath, filepath.Base(packConfig.File.Deb[idx].Ref))
			if ret, _ := fs.CheckFileExits(packConfig.File.Deb[idx].Path); ret {
				if hash := packConfig.File.Deb[idx].CheckDebHash(); hash {
					log.Logger.Infof("download skipped because of %s cached", packConfig.File.Deb[idx].Name)
				} else {
					log.Logger.Warnf("check deb hash failed! : ", packConfig.File.Deb[idx].Name)
					fs.RemovePath(packConfig.File.Deb[idx].Path)

					packConfig.File.Deb[idx].FetchDebFile(packConfig.File.Deb[idx].Path)
					log.Logger.Debugf("fetch deb path:[%d] %s", idx, packConfig.File.Deb[idx].Path)

					if ret := packConfig.File.Deb[idx].CheckDebHash(); !ret {
						log.Logger.Warnf("check deb hash failed! : ", packConfig.File.Deb[idx].Name)
						continue
					}
					log.Logger.Infof("download %s success.", packConfig.File.Deb[idx].Name)
				}
			} else {
				packConfig.File.Deb[idx].FetchDebFile(packConfig.File.Deb[idx].Path)
				log.Logger.Debugf("fetch deb path:[%d] %s", idx, packConfig.File.Deb[idx].Path)

				if ret := packConfig.File.Deb[idx].CheckDebHash(); !ret {
					log.Logger.Warnf("check deb hash failed! : ", packConfig.File.Deb[idx].Name)
					continue
				}
				log.Logger.Infof("download %s success.", packConfig.File.Deb[idx].Name)
			}

			// 提取 deb 包的相关数据
			packConfig.File.Deb[idx].ExtractDeb()
			// 依赖处理
			packConfig.File.Deb[idx].ResolveDepends(packConfig.Runtime.Source, packConfig.Runtime.DistroVersion)
			// 生成 build 阶段
			packConfig.File.Deb[idx].GenerateBuildScript()

			builder := linglong.LinglongBuder{
				Appid:       packConfig.File.Deb[idx].Package,
				Name:        packConfig.File.Deb[idx].Name,
				Version:     packConfig.File.Deb[idx].Version,
				Description: packConfig.File.Deb[idx].Desc,
				Runtime:     packConfig.Runtime.Id,
				Rversion:    packConfig.Runtime.Version,
				Sources:     packConfig.File.Deb[idx].Sources,
				Configure:   packConfig.File.Deb[idx].Configure,
				Install:     packConfig.File.Deb[idx].Install,
			}

			// 生成 linglong.yaml 文件
			linglongYamlPath := filepath.Join(appPath, comm.LinglongYaml)
			builder.CreateLinglongYamlBuilder(linglongYamlPath)
			log.Logger.Infof("generate %s success.", comm.LinglongYaml)

			// 构建玲珑包
			// if BuildLinglong {
			// 	if ret, msg, err := comm.ExecAndWait(10, "sh", "-c",
			// 		fmt.Sprintf("cd %s && ll-builder build", appPath)); err != nil {
			// 		log.Logger.Infof("build %s success.", packConfig.File.Deb[idx].Name)
			// 	} else {
			// 		log.Logger.Warnf("msg: %+v err:%+v, out: %+v", msg, err, ret)
			// 	}

			// 	// 导出玲珑包
			// 	if ret, msg, err := comm.ExecAndWait(10, "sh", "-c",
			// 		fmt.Sprintf("cd %s && ll-builder export", appPath)); err != nil {
			// 		log.Logger.Infof("%s export success.", packConfig.File.Deb[idx].Name)
			// 	} else {
			// 		log.Logger.Warnf("msg: %+v err:%+v, out: %+v", msg, err, ret)
			// 	}
			// }

		}
	}
	return nil
}
