package main

type dirWatcher struct {
	folder string
	files map[string]struct{}
}

func (w *dirWatcher) check() (added, removed []string, error) {
	files := make(map[string]struct{})
	info, err := os.ReadDir(folder)
	if err != nil {
		return
	}
	for _, fi := range info {
		if fi.IsDir() {
			continue
		}
		files[fi.Name()] = struct{}{}
	}
	for _, name := range w.files {
		if _, present := files[name]; !present {
			removed = append(removed, name)
		}
	}
	for _, name := range files {
		if _, present := w.files[name]; !present {
			added = append(added, name)
		}
	}
	return
}
