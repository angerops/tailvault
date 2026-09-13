//go:build darwin && cgo

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveFilePreservesBytesAndRestrictsPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "export.bin")
	if err := os.WriteFile(path, []byte("old content"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{{0, 255, 10, 13}, {}} {
		if err := saveFile(path, value); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, value) {
			t.Fatalf("export bytes differ: %v", err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("export mode %v", info.Mode())
		}
	}
	if err := saveFile(filepath.Dir(path), []byte("test")); err == nil {
		t.Fatal("write error was ignored")
	}
}
