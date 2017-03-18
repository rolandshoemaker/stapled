package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestDirWatcher(t *testing.T) {
	dw := newDirWatcher("")
	if dw != nil {
		t.Fatal("newDirWatcher with empty directory arg returned non-nil dirWatcher")
	}

	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Failed to create a temporary directory: %s", err)
	}
	defer os.RemoveAll(tempDir)

	dw = newDirWatcher(tempDir)
	a, r, err := dw.check()
	if err != nil {
		t.Fatalf("Failed to check temporary directory: %s", err)
	}
	if len(a) != 0 {
		t.Fatalf("Expected 0 added files in temporary directory, got %d", len(a))
	}
	if len(r) != 0 {
		t.Fatalf("Expected 0 removed files in temporary directory, got %d", len(r))
	}

	f, err := os.Create(filepath.Join(tempDir, "test-file"))
	if err != nil {
		t.Fatalf("Failed to create temporary file: %s", err)
	}

	a, r, err = dw.check()
	if err != nil {
		t.Fatalf("Failed to check temporary directory: %s", err)
	}
	if len(a) != 1 {
		t.Fatalf("Expected 1 added files in temporary directory, got %d", len(a))
	}
	if a[0] != f.Name() {
		t.Fatalf("Expected added file to be %s, got %s", f.Name(), a[0])
	}
	if len(r) != 0 {
		t.Fatalf("Expected 0 removed files in temporary directory, got %d", len(r))
	}

	err = os.Remove(f.Name())
	if err != nil {
		t.Fatalf("Failed to remove test file: %s", err)
	}

	a, r, err = dw.check()
	if err != nil {
		t.Fatalf("Failed to check temporary directory: %s", err)
	}
	if len(a) != 0 {
		t.Fatalf("Expected 0 added files in temporary directory, got %d", len(a))
	}
	if len(r) != 1 {
		t.Fatalf("Expected 1 removed files in temporary directory, got %d", len(r))
	}
	if r[0] != f.Name() {
		t.Fatalf("Expected removed file to be %s, got %s", f.Name(), r[0])
	}

	_, err = ioutil.TempDir(tempDir, "")
	if err != nil {
		t.Fatalf("Failed to create a temporary directory: %s", err)
	}
	a, r, err = dw.check()
	if err != nil {
		t.Fatalf("Failed to check temporary directory: %s", err)
	}
	if len(a) != 0 {
		t.Fatalf("Expected 0 added files in temporary directory, got %d", len(a))
	}
	if len(r) != 0 {
		t.Fatalf("Expected 0 removed files in temporary directory, got %d", len(r))
	}
}
