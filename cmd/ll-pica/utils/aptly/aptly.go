package aptly

// copy form aptly

import (
	"strings"
	"sync"

	"github.com/aptly-dev/aptly/aptly"
	"github.com/aptly-dev/aptly/cmd"
	"github.com/aptly-dev/aptly/deb"
	"github.com/aptly-dev/aptly/pgp"
	"github.com/aptly-dev/aptly/query"
	"github.com/aptly-dev/aptly/utils"
	"github.com/smira/flag"
	"pkg.deepin.com/linglong/pica/cmd/ll-pica/core/comm"
	"pkg.deepin.com/linglong/pica/cmd/ll-pica/utils/log"
)

// type Source struct {
// 	Kind string
// 	Hash string
// 	Url  string
// }

func GetPackageUrl(name string, sources []comm.Source) {
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
					// fmt.Printf("_------------------%s", task.File.DownloadURL())
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
	return sources
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
