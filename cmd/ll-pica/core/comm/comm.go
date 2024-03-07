/*
 * SPDX-FileCopyrightText: 2022 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

package comm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/smira/flag"

	"github.com/aptly-dev/aptly/aptly"
	"github.com/aptly-dev/aptly/cmd"
	"github.com/aptly-dev/aptly/deb"
	"github.com/aptly-dev/aptly/pgp"
	"github.com/aptly-dev/aptly/query"
	"github.com/aptly-dev/aptly/utils"
	"gopkg.in/yaml.v3"
	"pkg.deepin.com/linglong/pica/cmd/ll-pica/utils/fs"
	"pkg.deepin.com/linglong/pica/cmd/ll-pica/utils/log"
)

var (
	// app config with runtime
	ConfigInfo Config
	// convert config with app
)

type Config struct {
	Verbose    bool `yaml:"verbose"`
	DebugMode  bool
	Config     string `yaml:"config"`
	ConfigYaml string `yaml:"config-yaml"`
	WorkPath   string `yaml:"work-path"`
	// Initdir   string `yaml:"initdir"`
	// Basedir  string `yaml:"basedir"`
	// IsInited bool `yaml:"inited"`
	// Cache             bool   `yaml:"cache"`
	CachePath     string `yaml:"cache-path"`      // cache config path
	PackagePath   string `yaml:"package-path"`    // package config path
	BuildPackPath string `yaml:"build-pack-path"` // build package path
	// AppChannel   string
	// DebPath       string
	// IsRuntimeFetch    bool   `yaml:"runtime-fetched"`
	// IsRuntimeCheckout bool   `yaml:"runtime-checkedout"`
	// RuntimeOstreeDir  string `yaml:"runtime-ostreedir"`
	// RuntimeBasedir    string `yaml:"runtime-basedir"`
	// Rootfsdir         string `yaml:"rootfsdir"`
	// MountsItem        Mounts `yaml:"mounts"`
	// Yamlconfig        string
	// ExportDir         string `yaml:"exportdir"`
	// FilesSearchPath   string `yaml:"files-search-path"`
	AppUsername  string
	AppPasswords string
	AppId        string
	AppRepoUrl   string
	AppRepoName  string
	AppChannel   string
	AppKeyFile   string
	AppAuthType  int8
}

func (config *Config) Export() (bool, error) {
	// 检查新建export目录
	// if ret, err := fs.CheckFileExits(config.ExportDir); !ret && err != nil {
	// 	fs.CreateDir(config.ExportDir)
	// } else {
	// 	os.RemoveAll(config.ExportDir)
	// 	fs.CreateDir(config.ExportDir)
	// }

	// 定义需要拷贝的usr目录列表并处理
	// usrDirMap := map[string]string{
	// 	"usr/bin":   "files/bin",
	// 	"usr/share": "files/share",
	// 	"usr/lib":   "files/lib",
	// 	"etc":       "files/etc",
	// }

	// rsyncDir := func(timeout int, src, dst string) (stdout string, stderr string, err error) {
	// 	// 判断rsync命令是否存在
	// 	if _, err := exec.LookPath("rsync"); err != nil {
	// 		// return CopyFileKeepPath(src,dst)
	// 	}
	// 	return ExecAndWait(timeout, "rsync", "-av", src, dst)
	// }

	// 处理 initdir
	// for key, value := range usrDirMap {
	// 	keyPath := ConfigInfo.Initdir + "/" + key
	// 	valuePath := ConfigInfo.ExportDir + "/" + value
	// 	if ret, err := fs.CheckFileExits(keyPath); ret && err == nil {
	// 		fs.CreateDir(valuePath)
	// 		rsyncDir(30, keyPath+"/", valuePath)
	// 	}
	// }

	// 处理 basedir
	// for key, value := range usrDirMap {
	// 	keyPath := ConfigInfo.Basedir + "/" + key
	// 	valuePath := ConfigInfo.ExportDir + "/" + value
	// 	if ret, err := fs.CheckFileExits(keyPath); ret && err == nil {
	// 		fs.CreateDir(valuePath)
	// 		rsyncDir(30, keyPath+"/", valuePath)
	// 	}
	// }

	// 删除指定文件或者目录
	// removeFileList := []string{
	// 	"files/etc/apt/sources.list",
	// }
	// for _, dir := range removeFileList {
	// 	dirPath := ConfigInfo.ExportDir + "/" + dir
	// 	if ret, err := fs.CheckFileExits(dirPath); ret && err == nil {
	// 		ret, err = fs.RemovePath(dirPath)
	// 		if !ret && err != nil {
	// 			log.Logger.Errorf("remove %s err! \n", dirPath)
	// 			return false, errors.New("remove path err!")
	// 		}
	// 	}
	// }

	// 特殊处理applications、icons、dbus-1、systemd、mime、autostart、help等目录
	// specialDirList := []string{
	// 	"files/share/applications", // desktop
	// 	"files/share/icons",
	// 	"files/share/dbus-1",
	// 	"files/lib/systemd",
	// 	"files/share/mime",
	// 	"files/etc/xdg/autostart",
	// 	"files/share/help",
	// }
	// for _, dir := range specialDirList {
	// 	srcPath := ConfigInfo.ExportDir + "/" + dir + "/"
	// 	if ret, err := fs.CheckFileExits(srcPath); ret && err == nil {
	// 		dstPath := ConfigInfo.ExportDir + "/entries/" + fs.GetFileName(srcPath)
	// 		fs.CreateDir(dstPath)
	// 		rsyncDir(30, srcPath, dstPath)
	// 		os.RemoveAll(srcPath)
	// 	}
	// }

	// 拷贝处理/opt目录
	// srcOptPath := ConfigInfo.Basedir + "/opt/apps/" + DebConf.Deb[0].Name
	// log.Logger.Debugf("srcOptPath %s", srcOptPath)
	// if ret, err := fs.CheckFileExits(srcOptPath); ret && err == nil {
	// 	rsyncDir(30, srcOptPath+"/", ConfigInfo.ExportDir)
	// }

	// 处理icons目录下多余的icon-theme.cache文件
	// iconsPath := ConfigInfo.ExportDir + "/entries/icons"
	// if ret, err := fs.CheckFileExits(iconsPath); ret && err == nil {
	// 	// 遍历icons下的icon-theme.cache
	// 	filepath.Walk(iconsPath, func(path string, f os.FileInfo, err error) error {
	// 		if f == nil {
	// 			return err
	// 		}

	// 		if ret := strings.HasPrefix(f.Name(), "icon-theme.cache"); ret {
	// 			os.RemoveAll(path)
	// 		}

	// 		return nil
	// 	})
	// }

	// ConfigInfo.FilesSearchPath = ConfigInfo.ExportDir + "/files"
	return true, nil
}

// func (config *Config) fixDesktop(desktopFile, appid string) (bool, error) {
// 	newFileDesktop := fs.GetFilePPath(desktopFile) + "/bak-linglong.desktop"
// 	newFileDesktop = filepath.Clean(newFileDesktop)

// 	file, err := os.Open(desktopFile)
// 	if err != nil {
// 		log.Logger.Errorw("desktopFile open failed! : ", desktopFile)
// 		return false, err
// 	}
// 	defer file.Close()

// 	newFile, newFileErr := os.OpenFile(newFileDesktop, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
// 	if newFileErr != nil {
// 		log.Logger.Errorw("desktopFile open failed! : ", newFileDesktop)
// 		return false, newFileErr
// 	}
// 	defer newFile.Close()

// 	reader := bufio.NewReader(file)
// 	for {
// 		line, err := reader.ReadString('\n')
// 		if err != nil {
// 			if err == io.EOF {
// 				log.Logger.Debug("desktopFile read ok! : ", desktopFile)
// 				break
// 			} else {
// 				log.Logger.Errorw("read desktopFile failed! : ", desktopFile)
// 				return false, err
// 			}
// 		}
// 		// 去掉首尾空格
// 		line = strings.TrimSpace(line)
// 		// 处理Exec
// 		if strings.HasPrefix(line, "Exec=") {
// 			valueList := strings.Split(line, "=")
// 			newLine := strings.TrimRight(valueList[1], "\r\n")
// 			newLine = fs.TransExecToLl(newLine, appid)
// 			byteLine := []byte("Exec=" + newLine + "\n")
// 			newFile.Write(byteLine)
// 			// 处理TryExec
// 		} else if strings.HasPrefix(line, "TryExec=") {
// 			byteLine := []byte("TryExec=" + "\n")
// 			newFile.Write(byteLine)
// 			// 处理icon
// 		} else if strings.HasPrefix(line, "Icon=") {
// 			valueList := strings.Split(line, "=")
// 			newLine := strings.TrimRight(valueList[1], "\r\n")
// 			newLine = fs.TransIconToLl(newLine)
// 			byteLine := []byte("Icon=" + newLine + "\n")
// 			newFile.Write(byteLine)
// 		} else {
// 			newLine := strings.TrimRight(line, "\r\n")
// 			byteLine := []byte(newLine + "\n")
// 			newFile.Write(byteLine)
// 		}
// 	}
// 	newFile.Sync()

// 	if ret, err := fs.MoveFileOrDir(newFileDesktop, desktopFile); !ret && err != nil {
// 		log.Logger.Errorw("move test.desktop failed!")
// 		return false, err
// 	}

// 	return true, nil
// }

// func (config *Config) FixDesktop(appid string) (bool, error) {
// 	applicationsPath := config.ExportDir + "/entries/applications"
// 	applicationsPath = filepath.Clean(applicationsPath)
// 	if ret, err := fs.CheckFileExits(applicationsPath); !ret && err != nil {
// 		log.Logger.Errorw("applications dir not exists! : ", applicationsPath)
// 		return false, err
// 	}

// 	// 移除desktop目录里面多余文件
// 	dropfiles := []string{
// 		"bamf-2.index",
// 		"mimeinfo.cache",
// 	}
// 	for _, file := range dropfiles {
// 		dropfile := applicationsPath + "/" + file
// 		if ret, err := fs.CheckFileExits(dropfile); ret && err == nil {
// 			os.RemoveAll(dropfile)
// 		}
// 	}
// 	// 遍历desktop目录
// 	fileList, err := ioutil.ReadDir(applicationsPath)
// 	if err != nil {
// 		log.Logger.Errorw("readDir failed! : ", applicationsPath)
// 		return false, err

// 	}
// 	for _, fileinfo := range fileList {
// 		log.Logger.Debug("read dir : ", applicationsPath)
// 		desktopPath := applicationsPath + "/" + fileinfo.Name()
// 		if ret := strings.HasSuffix(desktopPath, ".desktop"); ret {
// 			// 处理desktop
// 			if ok, err := config.fixDesktop(desktopPath, appid); !ok && err != nil {
// 				return false, err
// 			}
// 		}
// 	}

// 	return true, nil
// }

// 当使用了-w 参数 ，没用 -f 参数时
func (config *Config) FixCachePath() (bool, error) {
	// 检查workdir是否存在
	if ret, err := fs.CheckFileExits(config.WorkPath); !ret || err != nil {
		return false, err
	}
	retWork := strings.HasPrefix(config.WorkPath, "/mnt/workdir")
	retCache := strings.HasPrefix(config.CachePath, "/mnt/workdir")
	if !retWork && retCache {
		config.CachePath = config.WorkPath + "/cache.yaml"
	}
	return true, nil
}

type MountItem struct {
	MountPoint string `yaml:"mountpoint"`
	Source     string `yaml:"source"`
	Type       string `yaml:"type"`
	TypeLive   string `yaml:"typelive"`
	IsRbind    bool   `yaml:"bind"`
}

type Mounts struct {
	Mounts map[string]MountItem `yaml:"mounts"`
}

func (ts Mounts) DoMountALL() []error {

	log.Logger.Debug("mount list: ", len(ts.Mounts))
	var errs []error
	if len(ts.Mounts) == 0 {
		return errs
	}

	var msg string
	var err error

	for _, item := range ts.Mounts {

		log.Logger.Debugf("mount: ", item.MountPoint, item.Source, item.Type, item.TypeLive, item.IsRbind)
		if IsRbind := item.IsRbind; IsRbind {

			// sudo mount --rbind /tmp/ /mnt/workdir/rootfs/tmp/
			_, msg, err = ExecAndWait(10, "mount", "--rbind", item.Source, item.MountPoint)
			if err != nil {
				log.Logger.Warnf("mount bind failed: ", msg, err)
				errs = append(errs, err)
				// continue
			}

		} else if item.TypeLive != "" {
			_, msg, err = ExecAndWait(10, "mount", item.TypeLive, "-t", item.Type, item.MountPoint)
			if err != nil {
				log.Logger.Warnf("mount failed: ", msg, err)
				errs = append(errs, err)
			}
		} else {
			_, msg, err = ExecAndWait(10, "mount", "-t", item.Type, item.Source, item.MountPoint)
			if err != nil {
				log.Logger.Warnf("mount failed: ", msg, err)
				errs = append(errs, err)
			}
		}

	}
	return errs
}

func (ts Mounts) DoUmountALL() []error {
	log.Logger.Debug("mount list: ", len(ts.Mounts))
	var errs []error
	if len(ts.Mounts) == 0 {
		return errs
	}

	for _, item := range ts.Mounts {
		log.Logger.Debugf("umount: ", item.MountPoint)
		_, msg, err := ExecAndWait(10, "umount", item.MountPoint)
		if err != nil {
			log.Logger.Warnf("umount failed: ", msg, err)
			errs = append(errs, err)
		} else {
			delete(ts.Mounts, item.MountPoint)
		}

	}
	return errs
}

// func (ts Mounts) DoUmountAOnce() []error {
// 	return nil
// 	log.Logger.Debugf("mount list: %v", len(ts.Mounts))
// 	var errs []error
// 	if len(ts.Mounts) == 0 {
// 		return nil
// 	}

// 	idx := 0
// UMOUNT_ONCE:
// 	_, msg, err := ExecAndWait(10, "umount", "-R", ConfigInfo.Rootfsdir)
// 	if err == nil {
// 		idx++
// 		if idx < 10 {
// 			goto UMOUNT_ONCE
// 		}
// 	} else {
// 		log.Logger.Warnf("umount success: ", msg, err)
// 		errs = append(errs, nil)
// 	}
// 	for _, item := range ts.Mounts {
// 		log.Logger.Debugf("umount: ", item.MountPoint)
// 		delete(ts.Mounts, item.MountPoint)

// 	}
// 	return errs
// }

// func (ts *Mounts) FillMountRules() {

// 	log.Logger.Debug("mount list: ", len(ts.Mounts))
// 	ts.Mounts[ConfigInfo.Rootfsdir+"/dev/pts"] = MountItem{ConfigInfo.Rootfsdir + "/dev/pts", "", "devpts", "devpts-live", false}
// 	ts.Mounts[ConfigInfo.Rootfsdir+"/sys"] = MountItem{ConfigInfo.Rootfsdir + "/sys", "", "sysfs", "sysfs-live", false}
// 	ts.Mounts[ConfigInfo.Rootfsdir+"/proc"] = MountItem{ConfigInfo.Rootfsdir + "/proc", "", "proc", "proc-live", false}
// 	ts.Mounts[ConfigInfo.Rootfsdir+"/tmp/"] = MountItem{ConfigInfo.Rootfsdir + "/tmp", "/tmp", "", "", true}
// 	ts.Mounts[ConfigInfo.Rootfsdir+"/etc/resolv.conf"] = MountItem{ConfigInfo.Rootfsdir + "/etc/resolv.conf", "/etc/resolv.conf", "", "", true}

// 	log.Logger.Debug("mount list: ", len(ts.Mounts))
// }

// exec and wait for command
func ExecAndWait(timeout int, name string, arg ...string) (stdout, stderr string, err error) {
	log.Logger.Debugf("cmd: %s %+v\n", name, arg)
	cmd := exec.Command(name, arg...)
	var bufStdout, bufStderr bytes.Buffer
	cmd.Stdout = &bufStdout
	cmd.Stderr = &bufStderr
	err = cmd.Start()
	if err != nil {
		err = fmt.Errorf("start fail: %w", err)
		return
	}

	// wait for process finished
	done := make(chan error)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(time.Duration(timeout) * time.Second):
		if err = cmd.Process.Kill(); err != nil {
			err = fmt.Errorf("timeout: %w", err)
			return
		}
		<-done
		err = fmt.Errorf("time out and process was killed")
	case err = <-done:
		stdout = bufStdout.String()
		stderr = bufStderr.String()
		if err != nil {
			err = fmt.Errorf("run: %w", err)
			return
		}
	}
	return
}

// package config info struct
type PackConfig struct {
	Runtime struct {
		Type    string `yaml:"type"`
		Id      string `yaml:"id"`
		Version string `yaml:"version"`
		Source  string `yaml:"source"`
		Distro  string `yaml:"distro"`
		Arch    string `yaml:"Arch"`
	} `yaml:"runtime"`
	File struct {
		Deb []Deb `yaml:"deb"`
	} `yaml:"file"`
}

// deb 包的信息
type Deb struct {
	Name         string `yaml:"name"`
	Id           string `yaml:"id"`
	Type         string `yaml:"type"`
	Ref          string `yaml:"ref"`
	Hash         string `yaml:"hash"`
	Path         string
	Package      string `yaml:"Package"`
	Version      string `yaml:"Version"`
	SHA256       string `yaml:"SHA256"`
	Desc         string `yaml:"Description"`
	Depends      string `yaml:"Depends"`
	Architecture string `yaml:"Architecture"`
	Filename     string `yaml:"Filename"`
	DependsList  []string
	FromAppStore bool
	// linglong.yaml manual
	Sources   []Source
	Configure []string
	Install   []string
}

type Source struct {
	Kind   string
	Digest string
	Url    string
}

const PackageConfigTMPL = `
runtime:
  type: ostree
  id: org.deepin.Runtime
  version: 23.0.0
  source: https://community-packages.deepin.com/deepin/beige/
  distro: beige
  Arch: amd64
file:
  deb:
    - type: repo
      id: com.baidu.baidunetdisk
      name: baidunetdisk
      ref: https://com-store-packages.uniontech.com/appstorev23/pool/appstore/c/com.baidu.baidunetdisk/com.baidu.baidunetdisk_4.17.7_amd64.deb
      kind: app
      hash: 

    # - type: repo
    #   id: com.baidu.baidunetdisk
    #   name: baidunetdisk
    #   ref: 
    #   kind: app
    #   hash: 

    # - type: local
    #   id: com.baidu.baidunetdisk
    #   name: baidunetdisk
    #   ref: /tmp/com.baidu.baidunetdisk_4.17.7_amd64.deb
    #   kind: app
    #   hash: 

`

func (p *PackConfig) CreatePackConfigYaml(path string) bool {
	tpl, err := template.New("package").Parse(PackageConfigTMPL)

	if err != nil {
		log.Logger.Warnf("parse template failed: %v", err)
		return false
	}

	// create save file
	log.Logger.Infof("create save file: %s", path)
	saveFd, ret := os.Create(path)
	if ret != nil {
		log.Logger.Fatalf("save to %s failed!", path)
		return false
	}
	defer saveFd.Close()

	// render template
	log.Logger.Debug("render template: ", p)
	tpl.Execute(saveFd, p)

	return true
}

func (d *Deb) CheckDebHash() bool {
	hash, err := GetFileSha256(d.Path)
	if d.Hash == "" {
		log.Logger.Debugf("%s not verify hash", d.Name)
		d.Hash = hash
		return true
	}
	if err != nil {
		log.Logger.Warn(err)
		d.Hash = hash
		return false
	}
	if hash == d.Hash {
		return true
	}

	return true
}

// FetchDebFile
func (d *Deb) FetchDebFile(dstPath string) bool {
	log.Logger.Debugf("FetchDebFile %s,ts:%v type:%s", dstPath, d, d.Type)

	if d.Type == "repo" {
		fs.CreateDir(fs.GetFilePPath(dstPath))

		if ret, msg, err := ExecAndWait(1<<20, "wget", "-O", dstPath, d.Ref); err != nil {

			log.Logger.Warnf("msg: %+v err:%+v, out: %+v", msg, err, ret)
			return false
		} else {
			log.Logger.Debugf("ret: %+v", ret)
		}

		if ret, err := fs.CheckFileExits(dstPath); ret {
			d.Path = dstPath
			return true
		} else {
			log.Logger.Warnf("downalod %s , err:%+v", dstPath, err)
			return false
		}
	} else if d.Type == "local" {
		if ret, err := fs.CheckFileExits(d.Ref); !ret {
			log.Logger.Warnf("not exist ! %s , err:%+v", d.Ref, err)
			return false
		}

		fs.CreateDir(fs.GetFilePPath(dstPath))
		if ret, msg, err := ExecAndWait(1<<8, "cp", "-v", d.Ref, dstPath); err != nil {
			log.Logger.Warnf("msg: %+v err:%+v, out: %+v", msg, err, ret)
			return false
		} else {
			log.Logger.Debugf("ret: %+v", ret)
		}

		if ret, err := fs.CheckFileExits(dstPath); ret {
			d.Path = dstPath
			return true
		} else {
			log.Logger.Warnf("downalod %s , err:%+v", dstPath, err)
			return false
		}
	}
	return false
}

func (d *Deb) ExtractDeb() bool {
	// apt-cache show
	if ret, msg, err := ExecAndWait(10, "apt-cache", "show", d.Path); err != nil {
		log.Logger.Warnf("msg: %+v err:%+v, out: %+v", msg, err, ret)
		return false
	} else {
		log.Logger.Debugf("ret: %+v", ret)
		// apt-cache show Unmarshal
		err = yaml.Unmarshal([]byte(ret), &d)
		if err != nil {
			log.Logger.Warnf("apt-cache show unmarshal error: %s", err)
			return false
		}
	}

	// 解压 deb 包，部分内容需要从解开的包中获取
	debDirPath := filepath.Join(filepath.Dir(d.Path), "deb")
	if ret, msg, err := ExecAndWait(1<<20, "dpkg-deb", "-x", d.Path, filepath.Join(filepath.Dir(d.Path), "deb")); err != nil {
		log.Logger.Warnf("msg: %+v err:%+v, out: %+v", msg, err, ret)
		return false
	} else {
		log.Logger.Debugf("ret: %+v", ret)
		// 应用商店的 deb 包，包含 opt/apps 目录，针对该目录是否存在，判定是否为应用商店包
		targetPath := filepath.Join(debDirPath, "opt/apps")
		if ret, _ := fs.CheckFileExits(targetPath); ret {
			log.Logger.Infof("%s is from app-store", d.Name)
			d.FromAppStore = true
		} else {
			log.Logger.Infof("%s is not from app-store", d.Name)
		}
	}

	if d.Type == "local" {
		d.Sources = append(d.Sources, Source{Kind: "local"})
	} else {
		d.Sources = append(d.Sources, Source{Kind: "file", Digest: d.Hash, Url: d.Ref})
	}
	// // 将依赖列表分割为子串（每个依赖项）
	// packages := strings.Split(d.Depends, ", ")
	// excludeList := []string{"libc6", "gcc-13"}

	// // 创建一个新的过滤后的依赖列表
	// filteredPackages := make([]string, 0)
	// for _, pkg := range packages {
	// 	if !contains(excludeList, pkg) { // 检查是否包含在排除列表中
	// 		filteredPackages = append(filteredPackages, pkg)
	// 	}
	// }

	// // 输出过滤后的依赖列表
	// newDependencies := strings.Join(filteredPackages, ", ")

	// fmt.Println(newDependencies)

	return true
}

// 解析依赖
func (d *Deb) ResolveDepends(source, distro string) {
	var (
		mirror_create_args []string
		// mirror_update_args []string
		filter = strings.Replace(d.Depends, ",", "|", -1)
	)

	// 删除掉aptly缓存的内容
	aptlyCache := filepath.Join(fs.GetHomePath(), ".aptly")
	if ret, _ := fs.CheckFileExits(aptlyCache); ret {
		log.Logger.Debugf("%s is existd!", aptlyCache)
		if ret, err := fs.RemovePath(aptlyCache); err != nil {
			log.Logger.Warnf("err:%+v, out: %+v", err, ret)
		}
	}

	root := cmd.RootCommand()
	root.UsageLine = "aptly"

	mirror_create_args = append(mirror_create_args, []string{
		"mirror",
		"create",
		"-ignore-signatures",
		"-architectures=" + d.Architecture,
		"-filter=" + filter,
		"-filter-with-deps",
		d.Name,
		source,
		distro,
	}...)

	initContext := false
	context := cmd.GetContext()
	if context == nil {
		initContext = true
	}
	cmd.Run(root, mirror_create_args, initContext)

	d.GetPackageSources(d.Name)

	// queue, downloadSize, _ = repo.BuildDownloadQueue(context.PackagePool(), collectionFactory.PackageCollection(),
	// 	collectionFactory.ChecksumCollection(nil), skipExistingPackages)
	// fmt.Printf("____________%+v", repo.PackageURL(task.File.DownloadURL()).String())

	// poolPath := filepath.Join(aptlyCache, "pool")
	// if ret, msg, err := ExecAndWait(10, "find", poolPath, "-type", "f"); err != nil {
	// 	log.Logger.Warnf("msg: %+v err:%+v, out: %+v", msg, err, ret)
	// } else {
	// 	log.Logger.Debugf("ret: %+v", ret)
	// 	fmt.Printf("----------------%s", ret)
	// }
}

func (d *Deb) GenerateBuildScript() {
	// 如果是应用商店的软件包
	if d.FromAppStore {
		debDirPath := filepath.Join(filepath.Dir(d.Path), "deb")

		// configure 阶段
		// 删除多余的 desktop 文件
		if ret, msg, err := ExecAndWait(10, "sh", "-c",
			fmt.Sprintf("find %s -name '*.desktop' | grep uos | xargs -I {} rm {}", debDirPath)); err != nil {
			log.Logger.Warnf("msg: %+v err:%+v, out: %+v", msg, err, ret)
		} else {
			log.Logger.Debugf("remove extra desktop file: %+v", ret)
			d.Configure = append(d.Configure, []string{
				"# remove extra desktop file",
				"find  workdir -name \"*.desktop\"|grep \"uos\"|xargs -I {} rm {}",
			}...)
		}

		// 读取desktop 文件
		if ret, msg, err := ExecAndWait(10, "sh", "-c",
			fmt.Sprintf("find %s -name '*.desktop' | grep entries", debDirPath)); err != nil {
			log.Logger.Warnf("msg: %+v err:%+v, out: %+v", msg, err, ret)
		} else {
			log.Logger.Debugf("ret: %+v", ret)

			execLine, msg, err := ExecAndWait(10, "sh", "-c", fmt.Sprintf("grep \"Exec=\" %s", ret))
			if err != nil {
				log.Logger.Warnf("msg: %+v err:%+v, out: %+v", msg, err, ret)
			} else {
				log.Logger.Debugf("read desktop get Exec %+v", execLine)
			}

			execFile := d.Name + ".sh"
			//获取 desktop 文件，Exec 行的内容,并且对字符串做处理
			pattern := regexp.MustCompile(`Exec=|"|\n`)
			execLine = pattern.ReplaceAllLiteralString(execLine, "")
			execSlice := strings.Split(execLine, " ")

			// 切割 Exec 命令
			binPath := strings.Split(execSlice[0], "/")
			// 获取可执行文件的名称
			binFile := binPath[len(binPath)-1]

			// 获取 files 和可执行文件之间路径的字符串
			extractPath := func() string {
				// 查找"files"在路径中的位置
				filesIndex := strings.Index(execSlice[0], "files/")
				if filesIndex == -1 {
					// 如果没有找到"files/"，返回原始路径
					return ""
				}

				// 找到该部分中最后一个斜杠的位置
				part := execSlice[0][filesIndex+len("files/"):]
				lastFolderIndex := strings.LastIndex(part, "/")
				if lastFolderIndex == -1 {
					// 如果没有找到斜杠，返回空
					return ""
				}
				return part[:lastFolderIndex]
			}
			ePath := extractPath()
			execSlice[0] = execFile

			lastIndex := len(execSlice) - 1
			execSlice[lastIndex] = strings.TrimSpace(execSlice[lastIndex])
			newExecLine := strings.Join(execSlice, " ")

			// 提取 Icon 字段
			iconLine, msg, err := ExecAndWait(10, "sh", "-c", fmt.Sprintf("grep \"Icon=\" %s", ret))
			if err != nil {
				log.Logger.Warnf("msg: %+v err:%+v, out: %+v", msg, err, ret)
			} else {
				log.Logger.Debugf("read desktop get Icon %+v", execLine)
			}
			iconSlice := strings.Split(iconLine, "Icon=")
			iconValue := fs.TransIconToLl(iconSlice[1])

			d.Configure = append(d.Configure, []string{
				"# modify desktop, Exec and Icon should not contanin absolut paths",
				"desktopPath=`find workdir -name \"*.desktop\" | grep entries`",
				"sed -i '/Exec*/c\\Exec=" + newExecLine + "' $desktopPath",
				"sed -i '/Icon*/c\\Icon=" + iconValue + "' $desktopPath",
				"# use a script as program",
				"echo \"#!/usr/bin/env bash\" > " + execFile,
				"echo \"cd $PREFIX/" + ePath + " && ./" + binFile + " \\$@\" >> " + execFile,
			}...)

		}

		// install 阶段
		d.Install = append(d.Install, []string{
			"# move files",
			"cp -r workdir/opt/apps/" + d.Id + "/entries/* $PREFIX/share",
			"cp -r workdir/opt/apps/" + d.Id + "/files/* $PREFIX",
			"install -m 0755 " + d.Name + ".sh $PREFIX/bin",
		}...)
	} else {
		// 如果不是应用商店的 deb 包
		// install 阶段
		d.Install = append(d.Install, []string{
			"# move files",
			"cp -r workdir/usr/* $PREFIX",
		}...)
	}
}

func GetPackageUrl(name, appid, source, distro, arch string) string {
	var (
		mirror_create_args []string
		mirror_update_args []string
	)

	// 删除掉aptly缓存的内容
	aptlyCache := filepath.Join(fs.GetHomePath(), ".aptly")
	if ret, _ := fs.CheckFileExits(aptlyCache); ret {
		log.Logger.Debugf("%s is existd!", aptlyCache)
		if ret, err := fs.RemovePath(aptlyCache); err != nil {
			log.Logger.Warnf("err:%+v, out: %+v", err, ret)
		}
	}

	root := cmd.RootCommand()
	root.UsageLine = "aptly"

	mirror_create_args = append(mirror_create_args, []string{
		"mirror",
		"create",
		"-ignore-signatures",
		"-architectures=" + arch,
		"-filter=" + name,
		name,
		source,
		distro,
	}...)
	cmd.Run(root, mirror_create_args, true)

	// verifier, err := getVerifier(context.Flags())
	// if err != nil {
	// 	log.Logger.Errorf("unable to initialize GPG verifier: %s", err)
	// }
	// context.Progress().Printf("Downloading & parsing package files...\n")
	// err = repo.DownloadPackageIndexes(context.Progress(), context.Downloader(), verifier, collectionFactory, false)
	// if err != nil {
	// 	log.Logger.Errorf("unable to update: %s", err)
	// }
	mirror_update_args = append(mirror_update_args, []string{
		"mirror",
		"update",
		"-ignore-signatures",
		name,
	}...)
	cmd.Run(root, mirror_update_args, false)

	context := cmd.GetContext()
	defer context.Shutdown()
	collectionFactory := context.NewCollectionFactory()
	repo, _ := collectionFactory.RemoteRepoCollection().ByName(name)

	err := collectionFactory.RemoteRepoCollection().LoadComplete(repo)
	if err != nil {
		log.Logger.Errorf("unable to update: %s", err)
	}

	// 获取到指定
	poolPath := filepath.Join(aptlyCache, "pool")
	if ret, msg, err := ExecAndWait(10, "find", poolPath, "-type", "f"); err != nil {
		log.Logger.Warnf("msg: %+v, not found %s, fallback to apt download", msg, name)
		if ret, _, err := ExecAndWait(10, "apt", "download", appid, "-y", "--print-uris"); err == nil {
			url := strings.Split(ret, " ")[0]
			url = strings.Replace(url, "'", "", 2)
			return url
		}
	} else {
		log.Logger.Debugf("poolPath ret: %+v", ret)
		// apt-cache show
		var deb Deb
		if info, msg, err := ExecAndWait(10, "sh", "-c",
			fmt.Sprintf("apt-cache show %s", ret)); err != nil {
			log.Logger.Warnf("msg: %+v err:%+v, out: %+v", msg, err, info)
		} else {
			log.Logger.Debugf("ret: %+v", info)
			// apt-cache show Unmarshal
			err = yaml.Unmarshal([]byte(info), &deb)
			if err != nil {
				log.Logger.Warnf("apt-cache show unmarshal error: %s", err)
			}
			return repo.PackageURL(deb.Filename).String()
		}
	}

	return ""
}

// type BaseConfig struct {
// 	SdkInfo struct {
// 		Base  []BaseInfo `yaml:"base"`
// 		Extra ExtraInfo  `yaml:"extra"`
// 	} `yaml:"sdk"`
// }

// type BaseInfo struct {
// 	Type   string `yaml:"type"`
// 	Ref    string `yaml:"ref"`
// 	Hash   string `yaml:"hash"`
// 	Remote string `yaml:"remote"`
// 	Path   string
// }

// func (ts *BaseInfo) CheckIsoHash() bool {
// 	if ts.Hash == "" {
// 		return false
// 	}
// 	hash, err := GetFileSha256(ts.Path)
// 	if err != nil {
// 		log.Logger.Warn(err)
// 		return false
// 	}
// 	if hash == ts.Hash {
// 		return true
// 	}

// 	return false
// }

// func (ts *BaseInfo) FetchIsoFile(workdir, isopath string) bool {
// 	//转化绝对路径
// 	isoAbsPath, _ := filepath.Abs(isopath)
// 	//如果下载目录不存在就创建目录
// 	fs.CreateDir(fs.GetFilePPath(isoAbsPath))
// 	if ts.Type != "iso" {
// 		return false
// 	}
// 	ts.Path = isoAbsPath

// 	if ret, msg, err := ExecAndWait(1<<20, "wget", "-O", ts.Path, ts.Ref); err != nil {
// 		log.Logger.Warnf("msg: %+v err:%+v, out: %+v", msg, err, ret)
// 		return false
// 	} else {
// 		log.Logger.Debugf("ret: %+v", ret)
// 	}

// 	if ret, err := fs.CheckFileExits(ts.Path); err != nil && !ret {
// 		log.Logger.Warnf("downalod %s , err:%+v", ts.Path, err)
// 		return false
// 	}
// 	return true
// }

// func (ts *BaseInfo) CheckoutOstree(target string) bool {
// 	// ConfigInfo.RuntimeBasedir = fmt.Sprintf("%s/runtimedir", ConfigInfo.Workdir)
// 	log.Logger.Debug("ostree checkout %s to %s", ts.Path, target)
// 	_, msg, err := ExecAndWait(10, "ostree", "checkout", "--repo", ts.Path, ts.Ref, target)

// 	if err != nil {
// 		log.Logger.Errorf("msg: %v ,err: %+v", msg, err)
// 		return false
// 	}
// 	return true
// }

// func (ts *BaseInfo) InitOstree(ostreePath string) bool {
// 	if ts.Type == "ostree" {
// 		log.Logger.Debug("ostree init")
// 		ts.Path = ostreePath
// 		_, msg, err := ExecAndWait(10, "ostree", "init", "--mode=bare-user-only", "--repo", ts.Path)
// 		if err != nil {
// 			log.Logger.Errorf("msg: %v ,err: %+v", msg, err)
// 			return false
// 		}
// 		log.Logger.Debug("ostree remote add", ts.Remote)

// 		_, msg, err = ExecAndWait(10, "ostree", "remote", "add", "runtime", ts.Remote, "--repo", ts.Path, "--no-gpg-verify")
// 		if err != nil {
// 			log.Logger.Errorf("msg: %+v err:%+v", msg, err)
// 			return false
// 		}

// 		log.Logger.Debug("ostree pull")
// 		_, msg, err = ExecAndWait(300, "ostree", "pull", "runtime", "--repo", ts.Path, "--mirror", ts.Ref)
// 		if err != nil {
// 			log.Logger.Errorf("msg: %+v err:%+v", msg, err)
// 			return false
// 		}

// 		return true
// 	}
// 	return false
// }

// type ExtraInfo struct {
// 	Repo    []string `yaml:"repo"`
// 	Package []string `yaml:"package"`
// 	Cmd     string   `yaml:"command"`
// }

// func (ts *ExtraInfo) WriteRootfsRepo(config Config) bool {
// 	if ret, err := fs.CheckFileExits(config.Rootfsdir + "/etc/apt/sources.list"); !ret && err != nil {
// 		log.Logger.Warnf("rootfs sources.list not exists ! ,err : %+v", err)
// 		return false
// 	}
// 	file, err := os.OpenFile(config.Rootfsdir+"/etc/apt/sources.list", os.O_RDWR|os.O_APPEND|os.O_TRUNC, 0644)
// 	if err != nil {
// 		log.Logger.Warnf("open sources.list failed! err: %+v", err)
// 		return false
// 	}
// 	defer file.Close()
// 	for _, value := range ts.Repo {
// 		if _, err := file.WriteString(value + "\n"); err != nil {
// 			log.Logger.Warnf("write sources.list failed! err : %+v", err)
// 			return false
// 		}
// 	}
// 	file.Sync()

// 	return true
// }

type ExtraShellTemplate struct {
	ExtraCommand string
	Verbose      bool
}

const EXTRA_COMMAND_TMPL = `#!/bin/bash
{{if .Verbose }}set -x {{end}}
function extra_command {
    {{if len .ExtraCommand }}{{.ExtraCommand}}{{end}}
    echo extra_command
}
{{if len .ExtraCommand }}extra_command{{end}}
echo init
`

// func (ts *ExtraInfo) RenderExtraShell(save string) (bool, error) {
// 	tpl, err := template.New("init").Parse(EXTRA_COMMAND_TMPL)

// 	if err != nil {
// 		log.Logger.Fatalf("parse deb shell template failed! ", err)
// 		return false, nil
// 	}

// 	extraShell := ExtraShellTemplate{"", ConfigInfo.Verbose}

// 	// PostCommand
// 	log.Logger.Debugf("cmd: %s", ts.Cmd)
// 	if len(ts.Cmd) > 0 {
// 		extraShell.ExtraCommand = ts.Cmd
// 	}

// 	// create save file
// 	log.Logger.Debug("extra shell save file: ", save)
// 	saveFd, ret := os.Create(save)
// 	if ret != nil {
// 		log.Logger.Warnf("save to %s failed!", save)
// 		return false, ret
// 	}
// 	defer saveFd.Close()

// 	// render template
// 	log.Logger.Debug("render template: ", extraShell)
// 	tpl.Execute(saveFd, extraShell)

// 	return true, nil
// }

func GetFileSha256(filename string) (string, error) {
	log.Logger.Debug("GetFileSha256 :", filename)
	hasher := sha256.New()
	s, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Logger.Warn(err)
		return "", err
	}
	_, err = hasher.Write(s)
	if err != nil {
		log.Logger.Warn(err)
		return "", err
	}

	sha256Sum := hex.EncodeToString(hasher.Sum(nil))
	log.Logger.Debug("file hash: ", sha256Sum)

	return sha256Sum, nil
}

func UmountPath(path string) bool {
	log.Logger.Debugf("umount path: %s", path)
	if ret, msg, err := ExecAndWait(10, "umount", path); err != nil {
		log.Logger.Debugf("umount path failed: %s %v \nout:%s", msg, err, ret)
		return false
	} else {
		log.Logger.Debugf("umount path %s \nout:%s", msg, ret)
		return true
	}
}

const (
	AppLoginFailed       int8 = -1
	AppLoginWithPassword int8 = iota
	AppLoginWithKeyfile
)

// App push with ll-builder
func LinglongBuilderWarp(t int8, conf *Config) (bool, error) {
	// max wait time for two MTL
	AppCommand := []string{
		"push",
	}
	AppConfigCommand := []string{
		"config",
	}
	if conf.AppChannel != "" {
		AppCommand = append(AppCommand, []string{
			"--channel",
			conf.AppChannel,
		}...)
	}
	if conf.AppRepoUrl != "" {
		AppCommand = append(AppCommand, []string{
			"--repo-url",
			conf.AppRepoUrl,
		}...)
	}
	if conf.AppRepoName != "" {
		AppCommand = append(AppCommand, []string{
			"--repo-name",
			conf.AppRepoName,
		}...)
	}

	switch t {
	case AppLoginWithPassword:
		AppConfigCommand = append(AppConfigCommand, []string{
			"--name",
			conf.AppUsername,
			"--password",
			conf.AppPasswords}...)
		// ll-builder config
		log.Logger.Infof("ll-builder %v", AppConfigCommand)
		if ret, msg, err := ExecAndWait(1<<12, "ll-builder", AppConfigCommand...); err == nil {
			log.Logger.Debugf("output: %v", ret)
		} else {
			log.Logger.Errorf("Exec stdout ret: %v,stderr msg %v", ret, msg)
			return false, err
		}
		break
	case AppLoginWithKeyfile:
		break
	default:
		return false, fmt.Errorf("not support")
	}

	AppCommand = append(AppCommand, string("--no-devel"))

	log.Logger.Debugf("command args: %v", AppCommand)

	// ll-builder import
	log.Logger.Infof("ll-builder import")
	if ret, msg, err := ExecAndWait(1<<12, "ll-builder", "import"); err == nil {
		log.Logger.Debugf("output: %v", ret)
	} else {
		log.Logger.Errorf("Exec stdout ret: %v,stderr msg %v", ret, msg)
		return false, err
	}

	// ll-builder push
	// ll-builder wait max timeout 3600 seconds wtf
	log.Logger.Infof("ll-builder %v", AppCommand)
	if ret, msg, err := ExecAndWait(1<<12, "ll-builder", AppCommand...); err == nil {
		log.Logger.Debugf("output: %v", ret)
		return true, nil
	} else {
		log.Logger.Errorf("Exec stdout ret: %v,stderr msg %v", ret, msg)
		return false, err
	}

}

// logger verbose
func LoggerVerbose(k string, s ...interface{}) {
	if ConfigInfo.Verbose || ConfigInfo.DebugMode {
		log.Logger.Infof(k, s)
	}
}

// 判断字符串是否包含在切片中的函数
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == strings.Trim(str, " ") {
			return true
		}
	}
	return false
}

func (d *Deb) GetPackageSources(name string) {
	context := cmd.GetContext()
	collectionFactory := context.NewCollectionFactory()
	repo, err := collectionFactory.RemoteRepoCollection().ByName(name)

	if err != nil {
		log.Logger.Errorf("unable to update: %s", err)
	}

	err = collectionFactory.RemoteRepoCollection().LoadComplete(repo)
	if err != nil {
		log.Logger.Errorf("unable to update: %s", err)
	}

	verifier, err := getVerifier(context.Flags())
	if err != nil {
		log.Logger.Errorf("unable to initialize GPG verifier: %s", err)
	}

	err = repo.Fetch(context.Downloader(), verifier)
	if err != nil {
		log.Logger.Errorf("unable to update: %s", err)
	}

	context.Progress().Printf("Downloading & parsing package files...\n")
	err = repo.DownloadPackageIndexes(context.Progress(), context.Downloader(), verifier, collectionFactory, false)
	if err != nil {
		log.Logger.Errorf("unable to update: %s", err)
	}

	if repo.Filter != "" {
		context.Progress().Printf("Applying filter...\n")
		var filterQuery deb.PackageQuery

		filterQuery, err = query.Parse(repo.Filter)
		if err != nil {
			log.Logger.Errorf("unable to update: %s", err)
		}

		var oldLen, newLen int
		oldLen, newLen, err = repo.ApplyFilter(context.DependencyOptions(), filterQuery, context.Progress())
		if err != nil {
			log.Logger.Errorf("unable to update: %s", err)
		}
		context.Progress().Printf("Packages filtered: %d -> %d.\n", oldLen, newLen)
	}

	var (
		downloadSize int64
		queue        []deb.PackageDownloadTask
	)

	context.Progress().Printf("Building download queue...\n")
	queue, downloadSize, err = repo.BuildDownloadQueue(context.PackagePool(), collectionFactory.PackageCollection(),
		collectionFactory.ChecksumCollection(nil), false)

	if err != nil {
		log.Logger.Errorf("unable to update: %s", err)
	}

	defer func() {
		// on any interruption, unlock the mirror
		err = context.ReOpenDatabase()
		if err == nil {
			repo.MarkAsIdle()
			collectionFactory.RemoteRepoCollection().Update(repo)
		}
	}()

	repo.MarkAsUpdating()
	err = collectionFactory.RemoteRepoCollection().Update(repo)
	if err != nil {
		log.Logger.Errorf("unable to update: %s", err)
	}

	err = context.CloseDatabase()
	if err != nil {
		log.Logger.Errorf("unable to update: %s", err)
	}

	context.GoContextHandleSignals()

	count := len(queue)
	context.Progress().Printf("Download queue: %d items (%s)\n", count, utils.HumanBytes(downloadSize))

	// Download from the queue
	context.Progress().InitBar(downloadSize, true, aptly.BarMirrorUpdateDownloadPackages)

	downloadQueue := make(chan int)

	var (
		errors  []string
		errLock sync.Mutex
	)

	pushError := func(err error) {
		errLock.Lock()
		errors = append(errors, err.Error())
		errLock.Unlock()
	}

	go func() {
		for idx := range queue {
			select {
			case downloadQueue <- idx:
			case <-context.Done():
				return
			}
		}
		close(downloadQueue)
	}()

	var wg sync.WaitGroup

	for i := 0; i < context.Config().DownloadConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case idx, ok := <-downloadQueue:
					if !ok {
						return
					}

					task := &queue[idx]

					var e error

					// provision download location
					task.TempDownPath, e = context.PackagePool().(aptly.LocalPackagePool).GenerateTempPath(task.File.Filename)
					if e != nil {
						pushError(e)
						continue
					}

					// download file...
					e = context.Downloader().DownloadWithChecksum(
						context,
						repo.PackageURL(task.File.DownloadURL()).String(),
						task.TempDownPath,
						&task.File.Checksums,
						false)

					// 返回 sources 列表，记录 kind, url, hash
					d.Sources = append(d.Sources, Source{Kind: "file", Digest: task.File.Checksums.SHA256, Url: repo.PackageURL(task.File.DownloadURL()).String()})

					if e != nil {
						pushError(e)
						continue
					}

					task.Done = true
				case <-context.Done():
					return
				}
			}
		}()
	}

	// Wait for all download goroutines to finish
	wg.Wait()

	context.Progress().ShutdownBar()

	err = context.ReOpenDatabase()
	if err != nil {
		log.Logger.Errorf("unable to update: %s", err)
	}

	// Import downloaded files
	context.Progress().InitBar(int64(len(queue)), false, aptly.BarMirrorUpdateImportFiles)

	for idx := range queue {
		context.Progress().AddBar(1)

		task := &queue[idx]

		if !task.Done {
			// download not finished yet
			continue
		}

		// and import it back to the pool
		task.File.PoolPath, err = context.PackagePool().Import(task.TempDownPath, task.File.Filename, &task.File.Checksums, true, collectionFactory.ChecksumCollection(nil))
		if err != nil {
			log.Logger.Errorf("unable to import file: %s", err)
		}

		// update "attached" files if any
		for _, additionalTask := range task.Additional {
			additionalTask.File.PoolPath = task.File.PoolPath
			additionalTask.File.Checksums = task.File.Checksums
		}
	}

	context.Progress().ShutdownBar()

	select {
	case <-context.Done():
		log.Logger.Errorf("unable to update: interrupted")
	default:
	}

	if len(errors) > 0 {
		log.Logger.Errorf("unable to update: download errors:\n  %s", strings.Join(errors, "\n  "))
	}

	repo.FinalizeDownload(collectionFactory, context.Progress())
	err = collectionFactory.RemoteRepoCollection().Update(repo)
	if err != nil {
		log.Logger.Errorf("unable to update: %s", err)
	}

	context.Progress().Printf("\nMirror `%s` has been successfully updated.\n", repo.Name)
}

func getVerifier(flags *flag.FlagSet) (pgp.Verifier, error) {
	context := cmd.GetContext()
	if cmd.LookupOption(context.Config().GpgDisableVerify, flags, "ignore-signatures") {
		return nil, nil
	}

	keyRings := flags.Lookup("keyring").Value.Get().([]string)

	verifier := context.GetVerifier()
	for _, keyRing := range keyRings {
		verifier.AddKeyring(keyRing)
	}

	err := verifier.InitKeyring()
	if err != nil {
		return nil, err
	}

	return verifier, nil
}
