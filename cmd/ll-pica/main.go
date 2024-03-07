/*
 * SPDX-FileCopyrightText: 2022 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
	"pkg.deepin.com/linglong/pica/cmd/ll-pica/core/comm"
	"pkg.deepin.com/linglong/pica/cmd/ll-pica/core/linglong"
	"pkg.deepin.com/linglong/pica/cmd/ll-pica/utils/fs"
	"pkg.deepin.com/linglong/pica/cmd/ll-pica/utils/log"
)

const (
	cacheDir     = ".cache/linglong-pica"
	packDir      = "package"
	cacheYaml    = "cache.yaml"
	packageYaml  = "package.yaml"
	linglongYaml = "linglong.yaml"
)

var (
	disableDevelop string
	BuildLinglong  bool // 是否进行构建
	PackConf       comm.PackConfig
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "init config template",
	Long:  `init config template.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		// 如果没指定 work 参数，使用默认的 work 目录 (~/.cache/linglong-pica)
		if comm.ConfigInfo.WorkPath == "" {
			comm.ConfigInfo.WorkPath = filepath.Join(fs.GetHomePath(), cacheDir)
			log.Logger.Infof("workdir path: %s", comm.ConfigInfo.WorkPath)
		} else {
			if workPath, err := filepath.Abs(comm.ConfigInfo.WorkPath); err != nil {
				log.Logger.Errorf("Trans %s err: %s ", comm.ConfigInfo.WorkPath, err)
				return
			} else {
				comm.ConfigInfo.WorkPath = workPath
				log.Logger.Infof("workdir path: %s", comm.ConfigInfo.WorkPath)
			}
		}

		// 创建 workdir
		if ret, _ := fs.CheckFileExits(comm.ConfigInfo.WorkPath); !ret {
			if ret, err := fs.CreateDir(comm.ConfigInfo.WorkPath); !ret {
				log.Logger.Errorf("create workdir %s failed: %s", comm.ConfigInfo.WorkPath, err)
				return
			}
		}

		if comm.ConfigInfo.Config == "package" {
			log.Logger.Infof("init %s template to %s", comm.ConfigInfo.Config, comm.ConfigInfo.WorkPath)
			comm.ConfigInfo.PackagePath = filepath.Join(comm.ConfigInfo.WorkPath, packageYaml)
			if ret, _ := fs.CheckFileExits(comm.ConfigInfo.PackagePath); !ret {
				PackConf.CreatePackConfigYaml(comm.ConfigInfo.PackagePath)
			}
		}

		comm.ConfigInfo.CachePath = filepath.Join(comm.ConfigInfo.WorkPath, cacheYaml)
		if ret, _ := fs.CheckFileExits(comm.ConfigInfo.CachePath); ret {
			// load cache.yaml
			log.Logger.Debugf("load: %s", comm.ConfigInfo.CachePath)
			cacheFd, err := ioutil.ReadFile(comm.ConfigInfo.CachePath)
			if err != nil {
				log.Logger.Warnf("read error: %s", err)
				return
			}

			if err = yaml.Unmarshal(cacheFd, &comm.ConfigInfo); err != nil {
				log.Logger.Warnf("unmarshal error: %s", err)
				return
			}
			log.Logger.Debugf("load cache.yaml success: %s", comm.ConfigInfo.CachePath)
		} else {
			log.Logger.Debug("Config Cache not exist")
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		cacheFd, err := yaml.Marshal(&comm.ConfigInfo)
		if err != nil {
			log.Logger.Errorf("convert to yaml failed!")
		}

		err = ioutil.WriteFile(comm.ConfigInfo.CachePath, cacheFd, 0644)
		if err != nil {
			log.Logger.Error("write cache.yaml failed!")
		}
	},
}

// convertCmd represents the convert command
var convertCmd = &cobra.Command{
	Use:   "convert",
	Short: "Convert deb to uab",
	Long: `Convert the deb to uab For example:
Convert:
	ll-pica init
	ll-pica convert  --config package.yaml --workdir /mnt/workdir --build true
	`,

	PreRun: func(cmd *cobra.Command, args []string) {
		if comm.ConfigInfo.Verbose {
			log.Logger.Info("verbose mode enabled")
			comm.ConfigInfo.Verbose = true
		}

		// 如果没指定 work 参数，使用默认的 work 目录 (~/.cache/linglong-pica)
		if comm.ConfigInfo.WorkPath == "" {
			comm.ConfigInfo.WorkPath = filepath.Join(fs.GetHomePath(), cacheDir)
			cachePath := filepath.Join(comm.ConfigInfo.WorkPath, cacheYaml)
			if ret, err := fs.CheckFileExits(cachePath); !ret {
				log.Logger.Fatal("cache-file required failed, please run ll-pica init", err)
				return
			}
			log.Logger.Infof("workdir path: %s", comm.ConfigInfo.WorkPath)
		} else {
			if workPath, err := filepath.Abs(comm.ConfigInfo.WorkPath); err != nil {
				log.Logger.Errorf("Trans %s err: %s ", comm.ConfigInfo.WorkPath, err)
				return
			} else {
				comm.ConfigInfo.WorkPath = workPath
			}
		}

		// 从 work 目录拼接路径，读取缓存文件，需要先运行 ll-pica init
		comm.ConfigInfo.CachePath = filepath.Join(comm.ConfigInfo.WorkPath, cacheYaml)
		if ret, err := fs.CheckFileExits(comm.ConfigInfo.CachePath); !ret {
			log.Logger.Fatal("can not found: %s, please run ll-pica init", err)
		} else {
			log.Logger.Debugf("load: %s", comm.ConfigInfo.CachePath)
			cacheFd, err := ioutil.ReadFile(comm.ConfigInfo.CachePath)
			if err != nil {
				log.Logger.Fatalf("read error: %s %s", err, err)
				return
			}
			err = yaml.Unmarshal(cacheFd, &comm.ConfigInfo)
			if err != nil {
				log.Logger.Fatalf("unmarshal error: %s", err)
				return
			}
		}

		log.Logger.Debug("load package config", comm.ConfigInfo.ConfigYaml)
		if comm.ConfigInfo.Config == "package" {
			packConfigFd, err := ioutil.ReadFile(comm.ConfigInfo.PackagePath)
			if err != nil {
				log.Logger.Errorf("get %s error: %v", comm.ConfigInfo.PackagePath, err)
				return
			}

			err = yaml.Unmarshal(packConfigFd, &PackConf)
			if err != nil {
				log.Logger.Errorf("error: %v", err)
				return
			}
			comm.ConfigInfo.ConfigYaml = packageYaml
		}

		// 创建 package, 存放软件包
		comm.ConfigInfo.BuildPackPath = filepath.Join(comm.ConfigInfo.WorkPath, packDir)
		if ret, err := fs.CheckFileExits(comm.ConfigInfo.BuildPackPath); !ret && err != nil {
			ret, err = fs.CreateDir(comm.ConfigInfo.BuildPackPath)
			if !ret || err != nil {
				log.Logger.Errorf("failed to create %s", comm.ConfigInfo.BuildPackPath)
			}
		}

		// package 目录下，新建包名对应的目录
		for idx := range PackConf.File.Deb {
			// fetch deb file
			if len(PackConf.File.Deb[idx].Id) > 0 {
				appPath := filepath.Join(comm.ConfigInfo.BuildPackPath, PackConf.File.Deb[idx].Id)
				if ret, err := fs.CheckFileExits(appPath); ret && err == nil {
					if !ret || err != nil {
						log.Logger.Errorf("failed to create %s", err)
					}
				} else {
					ret, err = fs.CreateDir(appPath)
					if !ret || err != nil {
						log.Logger.Errorf("failed to create %s", err)
					}
				}
			}
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		// fetch deb file
		// DebConfig
		log.Logger.Debugf("debConfig deb:%v", PackConf.File.Deb)
		for idx := range PackConf.File.Deb {
			// 如果 Ref 为空，type 为 apt, 就使用 apt download 获取 deb 链接。
			if PackConf.File.Deb[idx].Ref == "" {
				PackConf.File.Deb[idx].Ref = comm.GetPackageUrl(PackConf.File.Deb[idx].Name, PackConf.File.Deb[idx].Id, PackConf.Runtime.Source, PackConf.Runtime.Distro, PackConf.Runtime.Arch)
			}

			// fetch deb file
			if len(PackConf.File.Deb[idx].Ref) > 0 {
				// NOTE: work with go1.15 but feature not sure .
				appPath := filepath.Join(comm.ConfigInfo.BuildPackPath, PackConf.File.Deb[idx].Id)
				PackConf.File.Deb[idx].Path = filepath.Join(appPath, filepath.Base(PackConf.File.Deb[idx].Ref))
				if ret, _ := fs.CheckFileExits(PackConf.File.Deb[idx].Path); ret {
					if hash := PackConf.File.Deb[idx].CheckDebHash(); hash {
						log.Logger.Infof("download skipped because of %s cached", PackConf.File.Deb[idx].Name)
					} else {
						log.Logger.Warnf("check deb hash failed! : ", PackConf.File.Deb[idx].Name)
						fs.RemovePath(PackConf.File.Deb[idx].Path)

						PackConf.File.Deb[idx].FetchDebFile(PackConf.File.Deb[idx].Path)
						log.Logger.Debugf("fetch deb path:[%d] %s", idx, PackConf.File.Deb[idx].Path)

						if ret := PackConf.File.Deb[idx].CheckDebHash(); !ret {
							log.Logger.Warnf("check deb hash failed! : ", PackConf.File.Deb[idx].Name)
							continue
						}
						log.Logger.Infof("download %s success.", PackConf.File.Deb[idx].Name)
					}
				} else {
					PackConf.File.Deb[idx].FetchDebFile(PackConf.File.Deb[idx].Path)
					log.Logger.Debugf("fetch deb path:[%d] %s", idx, PackConf.File.Deb[idx].Path)

					if ret := PackConf.File.Deb[idx].CheckDebHash(); !ret {
						log.Logger.Warnf("check deb hash failed! : ", PackConf.File.Deb[idx].Name)
						continue
					}
					log.Logger.Infof("download %s success.", PackConf.File.Deb[idx].Name)
				}

				// 提取 deb 包的相关数据
				PackConf.File.Deb[idx].ExtractDeb()
				// 依赖处理
				PackConf.File.Deb[idx].ResolveDepends(PackConf.Runtime.Source, PackConf.Runtime.Distro)
				// 生成 build 阶段
				PackConf.File.Deb[idx].GenerateBuildScript()

				builder := linglong.LinglongBuder{
					Appid:       PackConf.File.Deb[idx].Package,
					Name:        PackConf.File.Deb[idx].Name,
					Version:     PackConf.File.Deb[idx].Version,
					Description: PackConf.File.Deb[idx].Desc,
					Runtime:     PackConf.Runtime.Id,
					Rversion:    PackConf.Runtime.Version,
					Sources:     PackConf.File.Deb[idx].Sources,
					Configure:   PackConf.File.Deb[idx].Configure,
					Install:     PackConf.File.Deb[idx].Install,
				}

				// 生成 linglong.yaml 文件
				linglongYamlPath := filepath.Join(appPath, linglongYaml)
				builder.CreateLinglongYamlBuilder(linglongYamlPath)
				log.Logger.Infof("generate %s success.", linglongYaml)

				// 构建玲珑包
				if BuildLinglong {
					if ret, msg, err := comm.ExecAndWait(10, "sh", "-c",
						fmt.Sprintf("cd %s && ll-builder build", appPath)); err != nil {
						log.Logger.Infof("build %s success.", PackConf.File.Deb[idx].Name)
					} else {
						log.Logger.Warnf("msg: %+v err:%+v, out: %+v", msg, err, ret)
					}

					// 导出玲珑包
					if ret, msg, err := comm.ExecAndWait(10, "sh", "-c",
						fmt.Sprintf("cd %s && ll-builder export", appPath)); err != nil {
						log.Logger.Infof("%s export success.", PackConf.File.Deb[idx].Name)
					} else {
						log.Logger.Warnf("msg: %+v err:%+v, out: %+v", msg, err, ret)
					}
				}

			}
		}
	},
	PostRun: func(cmd *cobra.Command, args []string) {
		cacheFd, err := yaml.Marshal(&comm.ConfigInfo)
		if err != nil {
			log.Logger.Errorf("convert to yaml failed!")
		}

		err = ioutil.WriteFile(comm.ConfigInfo.CachePath, cacheFd, 0644)
		if err != nil {
			log.Logger.Error("write cache.yaml failed!")
		}
	},
}

var pushCmd = &cobra.Command{
	Use:   "push",
	Short: "push app to repo",
	Long: `Push app to repo that used ll-builder push For example:
push:
	ll-pica push -u deepin -p deepin -i appid -w workdir
	`,
	PreRun: func(cmd *cobra.Command, args []string) {
		log.Logger.Infof("parse input app:", comm.ConfigInfo.AppId)

		// 转化工作目录为绝对路径
		if workPath, err := filepath.Abs(comm.ConfigInfo.WorkPath); err != nil {
			log.Logger.Errorf("Trans %s err: %s ", comm.ConfigInfo.WorkPath, err)
		} else {
			comm.ConfigInfo.WorkPath = workPath
		}

		// auth username
		if comm.ConfigInfo.AppUsername == "" || comm.ConfigInfo.AppPasswords == "" {
			comm.ConfigInfo.AppAuthType = comm.AppLoginWithKeyfile
		} else {
			log.Logger.Infof("app login with password")
			comm.ConfigInfo.AppAuthType = comm.AppLoginWithPassword
		}

		// AppKeyFile path
		comm.ConfigInfo.AppKeyFile = fs.GetHomePath() + "/.linglong/.user.json"
		// keyfile
		if ret, err := fs.CheckFileExits(comm.ConfigInfo.AppKeyFile); err != nil && !ret && (comm.ConfigInfo.AppAuthType == comm.AppLoginWithKeyfile) {
			log.Logger.Errorf("not found keyfile %v, please push with user and password!", comm.ConfigInfo.AppKeyFile)
			comm.ConfigInfo.AppAuthType = comm.AppLoginFailed
			return
		}

	},
	Run: func(cmd *cobra.Command, args []string) {
		log.Logger.Infof("app path %v", comm.ConfigInfo.WorkPath+"/"+comm.ConfigInfo.AppId+"/export/runtime")
		appDataPath := comm.ConfigInfo.WorkPath + "/" + comm.ConfigInfo.AppId + "/export/runtime"
		if ret, err := fs.CheckFileExits(appDataPath); err != nil && !ret {
			log.Logger.Errorf("app data dir not exist : %v", appDataPath)
			return
		}

		// 执行上传操作
		// 获取当前路径
		cwdPath, err := os.Getwd()
		if err != nil {
			log.Logger.Errorf("get cwd path Failed %v", err)
			return
		}
		// 进入appDataPath
		err = os.Chdir(appDataPath)
		if err != nil {
			log.Logger.Errorf("chdir failed: %s", err)
			return
		}

		if ret, err := comm.LinglongBuilderWarp(comm.ConfigInfo.AppAuthType, &comm.ConfigInfo); !ret {
			log.Logger.Errorf("%v push failed: %v", appDataPath, err)
			return
		}

		// 退出appDatapath
		err = os.Chdir(cwdPath)
		if err != nil {
			log.Logger.Errorf("chdir failed: %s", err)
			return
		}
	},
	PostRun: func(cmd *cobra.Command, args []string) {

	},
}

var rootCmd = &cobra.Command{
	Use:   "ll-pica",
	Short: "debian package convert linglong package",
	Long: `Convert the deb to uab. For example:
Simple:
	ll-pica init -c package -w work-dir
	ll-pica convert -c package.yaml -w work-dir
	ll-pica push -i appid -w work-dir
	ll-pica help
	`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(cmd.Use, "1.0.1")
	},
	PostRun: func(cmd *cobra.Command, args []string) {
		cmd.Usage()
	},
}

func main() {
	log.Logger = log.InitLog()
	defer log.Logger.Sync()

	rootCmd.AddCommand(initCmd)
	rootCmd.PersistentFlags().BoolVarP(&comm.ConfigInfo.Verbose, "verbose", "v", false, "verbose output")
	initCmd.Flags().StringVarP(&comm.ConfigInfo.Config, "config", "c", "package", "config")
	initCmd.Flags().StringVarP(&comm.ConfigInfo.WorkPath, "workdir", "w", "", "work directory")

	rootCmd.AddCommand(convertCmd)
	convertCmd.Flags().StringVarP(&comm.ConfigInfo.ConfigYaml, "config", "c", "package.yaml", "config")
	convertCmd.Flags().StringVarP(&comm.ConfigInfo.WorkPath, "workdir", "w", "", "work directory")
	convertCmd.Flags().BoolVarP(&BuildLinglong, "build", "b", false, "build linglong")

	rootCmd.AddCommand(pushCmd)
	pushCmd.Flags().StringVarP(&comm.ConfigInfo.AppUsername, "username", "u", "", "username")
	pushCmd.Flags().StringVarP(&comm.ConfigInfo.AppPasswords, "passwords", "p", "", "passwords")
	pushCmd.Flags().StringVarP(&comm.ConfigInfo.AppId, "appid", "i", "", "app id")
	pushCmd.Flags().StringVarP(&comm.ConfigInfo.AppChannel, "channel", "c", "linglong", "app channel")
	pushCmd.Flags().StringVarP(&comm.ConfigInfo.AppRepoUrl, "repo", "r", "", "repo url")
	pushCmd.Flags().StringVarP(&comm.ConfigInfo.AppRepoName, "reponame", "n", "", "repo name")
	pushCmd.Flags().StringVarP(&comm.ConfigInfo.WorkPath, "workdir", "w", "", "work directory")
	// if err := pushCmd.MarkFlagRequired("workdir"); err != nil {
	// 	log.Logger.Fatal("workdir required failed", err)
	// 	return
	// }

	if err := pushCmd.MarkFlagRequired("appid"); err != nil {
		log.Logger.Fatal("appid required failed", err)
		return
	}

	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// go build -ldflags '-X pkg.deepin.com/linglong/pica/cmd/ll-pica/utils/log.disableLogDebug=yes -X main.disableDevelop=yes'
	// fmt.Printf("disableDevelop: %s\n", disableDevelop)
	if disableDevelop != "" {
		log.Logger.Debugf("develop mode disable")
		comm.ConfigInfo.DebugMode = false
	} else {
		log.Logger.Debugf("develop mode enabled")
		comm.ConfigInfo.DebugMode = true
		// debug mode enable verbose mode
		comm.ConfigInfo.Verbose = true
	}

	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
