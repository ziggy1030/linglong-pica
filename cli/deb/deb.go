package deb

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/smira/flag"

	"github.com/aptly-dev/aptly/aptly"
	"github.com/aptly-dev/aptly/cmd"
	"github.com/aptly-dev/aptly/deb"
	"github.com/aptly-dev/aptly/pgp"
	"github.com/aptly-dev/aptly/query"
	"github.com/aptly-dev/aptly/utils"
	"gopkg.in/yaml.v3"

	"pkg.deepin.com/linglong/pica/cli/comm"
	"pkg.deepin.com/linglong/pica/tools/fs"
	"pkg.deepin.com/linglong/pica/tools/log"
)

type Deb struct {
	Name         string
	Id           string
	Type         string
	Ref          string
	Hash         string
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
	Sources      []Source
	Configure    []string
	Install      []string
}

type Source struct {
	Kind   string
	Digest string
	Url    string
}

func GetPackageUrl(name, appid, source, distro, arch string) string {
	aptlyCache := comm.AptlyCachePath()
	// 删除掉aptly缓存的内容
	if ret, _ := fs.CheckFileExits(aptlyCache); ret {
		log.Logger.Debugf("%s is existd!", aptlyCache)
		if ret, err := fs.RemovePath(aptlyCache); err != nil {
			log.Logger.Warnf("err:%+v, out: %+v", err, ret)
		}
	}

	root := cmd.RootCommand()
	root.UsageLine = "aptly"

	// 只过滤需要搜索的包
	args := []string{
		"mirror",
		"create",
		"-ignore-signatures",
		"-architectures=" + arch,
		"-filter=" + name,
		name,
		source,
		distro,
	}
	cmd.Run(root, args, cmd.GetContext() == nil)

	args = []string{
		"mirror",
		"update",
		"-ignore-signatures",
		name,
	}

	cmd.Run(root, args, cmd.GetContext() == nil)

	ctx := cmd.GetContext()
	defer ctx.Shutdown()
	// 搜索仓库数据库
	collectionFactory := ctx.NewCollectionFactory()
	repo, _ := collectionFactory.RemoteRepoCollection().ByName(name)

	err := collectionFactory.RemoteRepoCollection().LoadComplete(repo)
	if err != nil {
		log.Logger.Errorf("unable to update: %s", err)
	}

	// 获取到指定
	poolPath := filepath.Join(aptlyCache, "pool")
	if ret, msg, err := comm.ExecAndWait(10, "find", poolPath, "-type", "f"); err != nil {
		log.Logger.Warnf("msg: %+v, not found %s, fallback to apt download", msg, name)
		if ret, _, err := comm.ExecAndWait(10, "apt", "download", appid, "-y", "--print-uris"); err == nil {
			url := strings.Split(ret, " ")[0]
			url = strings.Replace(url, "'", "", 2)
			return url
		}
	} else {
		log.Logger.Debugf("poolPath ret: %+v", ret)
		// apt-cache show
		var deb Deb
		if info, msg, err := comm.ExecAndWait(10, "sh", "-c",
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

func (d *Deb) CheckDebHash() bool {
	hash, err := fs.GetFileSha256(d.Path)
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

		if ret, msg, err := comm.ExecAndWait(1<<20, "wget", "-O", dstPath, d.Ref); err != nil {
			log.Logger.Warnf("msg: %+v, out: %+v", msg, err, ret)
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
		if ret, msg, err := comm.ExecAndWait(1<<8, "cp", "-v", d.Ref, dstPath); err != nil {
			log.Logger.Fatalf("msg: %+v err:%+v, out: %+v", msg, err, ret)
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
	if ret, msg, err := comm.ExecAndWait(10, "sh", "-c",
		fmt.Sprintf("apt-cache show %s", d.Path)); err != nil {
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
	if ret, msg, err := comm.ExecAndWait(1<<20, "dpkg-deb", "-x", d.Path, filepath.Join(filepath.Dir(d.Path), "deb")); err != nil {
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
		args []string
		// mirror_update_args []string
		filter = strings.Replace(d.Depends, ",", "|", -1)
	)

	// 删除掉aptly缓存的内容
	aptlyCache := comm.AptlyCachePath()
	if ret, _ := fs.CheckFileExits(aptlyCache); ret {
		log.Logger.Debugf("%s is existd!", aptlyCache)
		if ret, err := fs.RemovePath(aptlyCache); err != nil {
			log.Logger.Warnf("err:%+v, out: %+v", err, ret)
		}
	}

	root := cmd.RootCommand()
	root.UsageLine = "aptly"

	args = []string{
		"mirror",
		"create",
		"-ignore-signatures",
		"-architectures=" + d.Architecture,
		"-filter=" + filter,
		"-filter-with-deps",
		d.Name,
		source,
		distro,
	}

	// initContext := false
	// context := cmd.GetContext()
	// if context == nil {
	// 	initContext = true
	// }
	cmd.Run(root, args, cmd.GetContext() == nil)

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
	execFile := "start.sh"
	// 如果是应用商店的软件包
	if d.FromAppStore {
		debDirPath := filepath.Join(filepath.Dir(d.Path), "deb")
		// configure 阶段
		// 删除多余的 desktop 文件
		if ret, msg, err := comm.ExecAndWait(10, "sh", "-c",
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
		if ret, msg, err := comm.ExecAndWait(10, "sh", "-c",
			fmt.Sprintf("find %s -name '*.desktop' | grep entries", debDirPath)); err != nil {
			log.Logger.Warnf("msg: %+v err:%+v, out: %+v", msg, err, ret)
		} else {
			log.Logger.Debugf("ret: %+v", ret)

			execLine, msg, err := comm.ExecAndWait(10, "sh", "-c", fmt.Sprintf("grep \"Exec=\" %s", ret))
			if err != nil {
				log.Logger.Warnf("msg: %+v err:%+v, out: %+v", msg, err, ret)
			} else {
				log.Logger.Debugf("read desktop get Exec %+v", execLine)
			}

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
			iconLine, msg, err := comm.ExecAndWait(10, "sh", "-c", fmt.Sprintf("grep \"Icon=\" %s", ret))
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
				"echo \"export LD_LIBRARY_PATH=/opt/apps/" + d.Id + "/files/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu\" >> " + execFile,
				"echo \"cd $PREFIX/" + ePath + " && ./" + binFile + " \\$@\" >> " + execFile,
			}...)

		}

		// install 阶段
		d.Install = append(d.Install, []string{
			"install -m 0755 " + execFile + " $PREFIX/bin",
			"# move files",
			"cp -r workdir/opt/apps/" + d.Id + "/entries/* $PREFIX/share",
			"cp -r workdir/opt/apps/" + d.Id + "/files/* $PREFIX",
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
