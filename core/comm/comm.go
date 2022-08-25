/*
 * Copyright (c) 2022. Uniontech Software Ltd. All rights reserved.
 *
 * Author: Heysion Y. <heysion@deepin.com>
 *
 * Maintainer: Heysion Y. <heysion@deepin.com>
 *
 * SPDX-License-Identifier: GNU General Public License v3.0 or later
 */
package comm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	. "ll-pica/utils/fs"
	. "ll-pica/utils/log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

// app config with runtime

var ConfigInfo Config
var TransInfo Config
var DebConf DebConfig

type Config struct {
	Verbose           bool   `yaml:"verbose"`
	Config            string `yaml:"config"`
	Workdir           string `yaml:"workdir"`
	Basedir           string `yaml:"basedir"`
	IsInited          bool   `yaml:"inited"`
	Cache             bool   `yaml:"cache"`
	CachePath         string `yaml:"cache-path"`
	DebWorkdir        string `yaml:"debdir"`
	DebPath           string
	IsRuntimeFetch    bool   `yaml:"runtime-fetched"`
	IsRuntimeCheckout bool   `yaml:"runtime-checkedout"`
	RuntimeOstreeDir  string `yaml:"runtime-ostreedir"`
	RuntimeBasedir    string `yaml:"runtime-basedir"`
	IsIsoDownload     bool   `yaml:"iso-downloaded"`
	IsoPath           string `yaml:"iso-path"`
	IsoMountDir       string `yaml:"iso-mount-dir"`
	IsIsoChecked      bool   `yaml:"iso-checked"`
	Rootfsdir         string `yaml:"rootfsdir"`
	MountsItem        Mounts `yaml:"mounts"`
	Yamlconfig        string
	ExportDir         string `yaml:"exportdir"`
	FilesSearchPath   string `yaml:"files-search-path"`
}

type MountItem struct {
	MountPoint string `yaml:"mountpoint"`
	Source     string `yaml:"source"`
	Type       string `yaml:"type"`
	IsRbind    bool   `yaml:"bind"`
}

type Mounts struct {
	Mounts map[string]MountItem `yaml:"mounts"`
}

func (ts Mounts) DoMountALL() []error {

	logger.Debug("mount list: ", len(ts.Mounts))
	var errs []error
	if len(ts.Mounts) == 0 {
		return errs
	}

	var msg string
	var err error

	for _, item := range ts.Mounts {

		logger.Debugf("mount: ", item.MountPoint, item.Source, item.Type, item.IsRbind)
		if IsRbind := item.IsRbind; IsRbind {

			// sudo mount --rbind /tmp/ /mnt/workdir/rootfs/tmp/
			_, msg, err = ExecAndWait(10, "mount", "--rbind", item.Source, item.MountPoint)
			if err != nil {
				logger.Warnf("mount bind failed: ", msg, err)
				errs = append(errs, err)
			}

			// sudo mount --make-rslave /mnt/workdir/rootfs/tmp/
			_, msg, err = ExecAndWait(10, "mount", "--make-rslave", item.MountPoint)
			if err != nil {
				logger.Warnf("mount bind rslave failed: ", msg, err)
				errs = append(errs, err)
			}

		} else {
			_, msg, err = ExecAndWait(10, "mount", "-t", item.Type, item.Source, item.MountPoint)
			if err != nil {
				logger.Warnf("mount failed: ", msg, err)
				errs = append(errs, err)
			}
		}

	}
	return errs
}

func (ts Mounts) DoUmountALL() []error {
	logger.Debug("mount list: ", len(ts.Mounts))
	var errs []error
	if len(ts.Mounts) == 0 {
		return errs
	}

	for _, item := range ts.Mounts {
		logger.Debugf("umount: ", item.MountPoint)
		_, msg, err := ExecAndWait(10, "umount", item.MountPoint)
		if err != nil {
			logger.Warnf("umount failed: ", msg, err)
			errs = append(errs, err)
		} else {
			delete(ts.Mounts, item.MountPoint)
		}

	}
	return errs
}

func (ts Mounts) DoUmountAOnce() []error {
	return nil
	logger.Debug("mount list: ", len(ts.Mounts))
	var errs []error
	if len(ts.Mounts) == 0 {
		return nil
	}

	idx := 0
UMOUNT_ONCE:
	_, msg, err := ExecAndWait(10, "umount", "-R", ConfigInfo.Rootfsdir)
	if err == nil {
		idx++
		if idx < 10 {
			goto UMOUNT_ONCE
		}
	} else {
		logger.Warnf("umount success: ", msg, err)
		errs = append(errs, nil)
	}
	for _, item := range ts.Mounts {
		logger.Debugf("umount: ", item.MountPoint)
		delete(ts.Mounts, item.MountPoint)

	}
	return errs
}

func (ts *Mounts) FillMountRules() {

	logger.Debug("mount list: ", len(ts.Mounts))
	ts.Mounts[ConfigInfo.Rootfsdir+"/dev/"] = MountItem{ConfigInfo.Rootfsdir + "/dev/", "/dev/", "tmpfs", true}
	ts.Mounts[ConfigInfo.Rootfsdir+"/sys/"] = MountItem{ConfigInfo.Rootfsdir + "/sys/", "/sys/", "sysfs", true}
	ts.Mounts[ConfigInfo.Rootfsdir+"/tmp/"] = MountItem{ConfigInfo.Rootfsdir + "/tmp/", "/tmp/", "tmpfs", true}
	ts.Mounts[ConfigInfo.Rootfsdir+"/etc/resolv.conf"] = MountItem{ConfigInfo.Rootfsdir + "/etc/resolv.conf", "/etc/resolv.conf", "tmpfs", true}

	ts.Mounts[ConfigInfo.Rootfsdir+"/proc/"] = MountItem{ConfigInfo.Rootfsdir + "/proc/", "none", "proc", false}

	logger.Debug("mount list: ", len(ts.Mounts))
}

func (config *Config) Export() (bool, error) {
	// 检查新建export目录
	if ret, err := CheckFileExits(config.ExportDir); !ret && err != nil {
		CreateDir(config.ExportDir)
	} else {
		os.RemoveAll(config.ExportDir)
		CreateDir(config.ExportDir)
	}

	// 定义需要拷贝的usr目录列表并处理
	usrDirMap := map[string]string{
		"usr/bin":   "files/bin",
		"usr/share": "files/share",
		"usr/lib":   "files/lib",
		"etc":       "files/etc",
	}

	rsyncDir := func(timeout int, src, dst string) (stdout string, stderr string, err error) {
		// 判断rsync命令是否存在
		if _, err := exec.LookPath("rsync"); err != nil {
			// return CopyFileKeepPath(src,dst)
		}
		return ExecAndWait(timeout, "rsync", "-av", src, dst)
	}

	for key, value := range usrDirMap {
		keyPath := ConfigInfo.Basedir + "/" + key
		valuePath := ConfigInfo.ExportDir + "/" + value
		if ret, err := CheckFileExits(keyPath); ret && err == nil {
			CreateDir(valuePath)
			rsyncDir(30, keyPath+"/", valuePath)
		}
	}

	// 拷贝处理/opt目录
	srcOptPath := ConfigInfo.Basedir + "/opt/apps/" + DebConf.Info.Appid
	if ret, err := CheckFileExits(srcOptPath); ret && err == nil {
		rsyncDir(30, srcOptPath+"/", ConfigInfo.ExportDir)
	}

	// 特殊处理applications、icons、dbus-1、systemd、mime、autostart、help等目录
	specialDirList := []string{
		"files/share/applications",
		"files/share/icons",
		"files/share/dbus-1",
		"files/lib/systemd",
		"files/share/mime",
		"files/etc/xdg/autostart",
		"files/share/help",
	}
	for _, dir := range specialDirList {
		srcPath := ConfigInfo.ExportDir + "/" + dir + "/"
		if ret, err := CheckFileExits(srcPath); ret && err == nil {
			dstPath := ConfigInfo.ExportDir + "/entries/" + GetFileName(srcPath)
			CreateDir(dstPath)
			rsyncDir(30, srcPath, dstPath)
			os.RemoveAll(srcPath)
		}
	}
	ConfigInfo.FilesSearchPath = ConfigInfo.ExportDir + "/files"
	return true, nil
}

var logger *zap.SugaredLogger

func init() {
	logger = InitLog()
}

// exec and wait for command
func ExecAndWait(timeout int, name string, arg ...string) (stdout, stderr string, err error) {
	logger.Debugf("cmd: %s %+v\n", name, arg)
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

// deb config info struct
type DebConfig struct {
	Info struct {
		Appid       string `yaml:"appid"`
		Name        string `yaml:"name"`
		Version     string `yaml:"version"`
		Description string `yaml:"description"`
		Kind        string `yaml:"kind"`
		Arch        string `yaml:"arch"`
	} `yaml:"info"`
	FileElement struct {
		Deb     []DebInfo `yaml:"deb"`
		Package []string  `yaml:"add-package"`
	} `yaml:"file"`
	BuildInfo struct{} `yaml:"build"`
}

type DebInfo struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"`
	Ref  string `yaml:"ref"`
	Hash string `yaml:"hash"`
	Path string
}

func (ts *DebInfo) CheckDebHash() bool {
	if ts.Hash == "" {
		return false
	}
	hash, err := GetFileSha256(ts.Path)
	if err != nil {
		logger.Warn(err)
		return false
	}
	if hash == ts.Hash {
		return true
	}

	return false
}

func (ts *DebInfo) FetchDebFile(dirPath string) bool {

	logger.Debugf("FetchDebFile :%v", ts)
	if ts.Type == "repo" {
		// ts.path = fmt.Sprintf("%s/", dirPath)

		_, msg, err := ExecAndWait(1<<20, "wget", "-P", dirPath, ts.Ref)
		if err != nil {

			logger.Errorf("msg: %+v err:%+v", msg, err)
			return false
		}
		debFilePath, err := filepath.Glob(fmt.Sprintf("%s/%s_*.deb", dirPath, ts.Name))
		if err != nil {
			logger.Error(debFilePath)
			return false
		}
		logger.Debugf("debFilePath: %+v [0]:%s", debFilePath, debFilePath[0])
		if err, msg := CheckFileExits(debFilePath[0]); err {
			ts.Path = debFilePath[0]
			return true
		} else {
			logger.Errorf("msg: %+v err:%+v", msg, err)
			return false
		}
	}
	return false
}

func (ts *DebConfig) MergeInfo(t *DebConfig) bool {
	if ts.Info.Appid == "" {
		ts.Info.Appid = t.Info.Appid
	}
	if ts.Info.Name == "" {
		ts.Info.Name = t.Info.Name
	}
	if ts.Info.Version == "" {
		ts.Info.Version = t.Info.Version
	}
	if ts.Info.Description == "" {
		ts.Info.Description = t.Info.Description
	}
	if ts.Info.Kind == "" {
		ts.Info.Kind = t.Info.Kind
	}
	if ts.Info.Arch == "" {
		ts.Info.Arch = t.Info.Arch
	}
	return true
}

type BaseConfig struct {
	SdkInfo struct {
		Base  []BaseInfo `yaml:"base"`
		Extra ExtraInfo  `yaml:"extra"`
	} `yaml:"sdk"`
}

type BaseInfo struct {
	Type   string `yaml:"type"`
	Ref    string `yaml:"ref"`
	Hash   string `yaml:"hash"`
	Remote string `yaml:"remote"`
	Path   string
}

func (ts *BaseInfo) CheckIsoHash() bool {
	if ts.Hash == "" {
		return false
	}
	hash, err := GetFileSha256(ts.Path)
	if err != nil {
		logger.Warn(err)
		return false
	}
	if hash == ts.Hash {
		return true
	}

	return false
}

func (ts *BaseInfo) FetchIsoFile(workdir, isopath string) bool {
	//转化绝对路径
	isoAbsPath, _ := filepath.Abs(isopath)
	//如果下载目录不存在就创建目录
	CreateDir(GetFilePPath(isoAbsPath))
	if ts.Type == "iso" {
		ts.Path = isoAbsPath
		_, msg, err := ExecAndWait(1<<20, "wget", "-O", ts.Path, ts.Ref)
		if err != nil {
			logger.Errorf("msg: %+v err:%+v", msg, err)
			return false
		}
		return true
	}
	return false
}

func (ts *BaseInfo) CheckoutOstree(target string) bool {
	// ConfigInfo.RuntimeBasedir = fmt.Sprintf("%s/runtimedir", ConfigInfo.Workdir)
	logger.Debug("ostree checkout %s to %s", ts.Path, target)
	_, msg, err := ExecAndWait(10, "ostree", "checkout", "--repo", ts.Path, ts.Ref, target)

	if err != nil {
		logger.Errorf("msg: %v ,err: %+v", msg, err)
		return false
	}
	return true
}

func (ts *BaseInfo) InitOstree(ostreePath string) bool {
	if ts.Type == "ostree" {
		logger.Debug("ostree init")
		ts.Path = ostreePath
		_, msg, err := ExecAndWait(10, "ostree", "init", "--mode=bare-user-only", "--repo", ts.Path)
		if err != nil {
			logger.Errorf("msg: %v ,err: %+v", msg, err)
			return false
		}
		logger.Debug("ostree remote add", ts.Remote)

		_, msg, err = ExecAndWait(10, "ostree", "remote", "add", "runtime", ts.Remote, "--repo", ts.Path, "--no-gpg-verify")
		if err != nil {
			logger.Errorf("msg: %+v err:%+v", msg, err)
			return false
		}

		logger.Debug("ostree pull")
		_, msg, err = ExecAndWait(300, "ostree", "pull", "runtime", "--repo", ts.Path, "--mirror", ts.Ref)
		if err != nil {
			logger.Errorf("msg: %+v err:%+v", msg, err)
			return false
		}

		return true
	}
	return false
}

type ExtraInfo struct {
	repo    []string `yaml:"repo"`
	Package []string `yaml:"package"`
	Cmd     []string `yaml:"command"`
}

func GetFileSha256(filename string) (string, error) {
	logger.Debug("GetFileSha256 :", filename)
	hasher := sha256.New()
	s, err := ioutil.ReadFile(filename)
	if err != nil {
		logger.Warn(err)
		return "", err
	}
	_, err = hasher.Write(s)
	if err != nil {
		logger.Warn(err)
		return "", err
	}

	sha256Sum := hex.EncodeToString(hasher.Sum(nil))
	logger.Debug("file hash: ", sha256Sum)

	return sha256Sum, nil
}
