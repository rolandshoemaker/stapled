package main

import (
	"io/ioutil"
	"path/filepath"
)

type dirWatcher struct {
	folder string
	files  map[string]struct{}
}

func newDirWatcher(folder string) *dirWatcher {
	if folder != "" {
		return &dirWatcher{folder, make(map[string]struct{})}
	}
	return nil
}

func (w *dirWatcher) check() (added, removed []string, err error) {
	files := make(map[string]struct{})
	info, err := ioutil.ReadDir(w.folder)
	if err != nil {
		return
	}
	for _, fi := range info {
		if fi.IsDir() {
			continue
		}
		files[fi.Name()] = struct{}{}
	}
	for name := range w.files {
		if _, present := files[name]; !present {
			removed = append(removed, filepath.Join(w.folder, name))
			delete(w.files, name)
		}
	}
	for name := range files {
		if _, present := w.files[name]; !present {
			w.files[name] = struct{}{}
			added = append(added, filepath.Join(w.folder, name))
		}
	}
	return
}
