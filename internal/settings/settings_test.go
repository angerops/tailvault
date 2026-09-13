package settings

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFirstRunAndPersistenceAcrossStoreInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "TailVault", "settings.json")
	store := Store{Path: path}
	saved, err := store.Load()
	if err != nil || saved.Server != "" {
		t.Fatalf("first run: %#v, %v", saved, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("first launch created a settings file")
	}
	if err := store.Save(" https://SECRETS.example.ts.net:8443/ "); err != nil {
		t.Fatal(err)
	}
	restarted := Store{Path: path}
	saved, err = restarted.Load()
	if err != nil || saved.Server != "https://secrets.example.ts.net:8443" {
		t.Fatalf("saved address did not survive restart: %#v, %v", saved, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("settings file should be private to the macOS user")
	}
	if err := restarted.Save("https://replacement.example.ts.net"); err != nil {
		t.Fatal(err)
	}
	saved, err = store.Load()
	if err != nil || saved.Server != "https://replacement.example.ts.net" {
		t.Fatal("new address did not replace the previous setting")
	}
}

func TestInvalidOrFailedSavePreservesExistingSettings(t *testing.T) {
	store := Store{Path: filepath.Join(t.TempDir(), "settings.json")}
	if err := store.Save("https://secrets.example.ts.net"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(store.Path)
	if err := store.Save("http://insecure.example"); err == nil {
		t.Fatal("accepted HTTP")
	}
	after, _ := os.ReadFile(store.Path)
	if string(before) != string(after) {
		t.Fatal("invalid save replaced existing settings")
	}
	blocked := Store{Path: filepath.Join(store.Path, "settings.json")}
	if err := blocked.Save("https://replacement.example.ts.net"); err == nil {
		t.Fatal("expected filesystem failure")
	}
	after, _ = os.ReadFile(store.Path)
	if string(before) != string(after) {
		t.Fatal("failed save replaced existing settings")
	}
}

func TestCorruptSettingsDoNotChooseADefaultServer(t *testing.T) {
	store := Store{Path: filepath.Join(t.TempDir(), "settings.json")}
	for _, value := range []string{`not JSON`, `{}`, `{"server":"http://insecure.example"}`} {
		if err := os.WriteFile(store.Path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		saved, err := store.Load()
		if err == nil || saved.Server != "" {
			t.Fatal("corrupt settings should require the user to configure a server")
		}
	}
}

func TestServerAddressValidation(t *testing.T) {
	for _, raw := range []string{"", "secrets.example.ts.net", "http://secrets.example.ts.net", "https://user:pass@secrets.example.ts.net", "https://secrets.example.ts.net/api", "https://secrets.example.ts.net?x=1", "https://secrets.example.ts.net?", "https://secrets.example.ts.net#fragment", "https://secrets.example.ts.net#", "https://secrets.example.ts.net:0", "https://secrets.example.ts.net:65536", "https://secrets.example.ts.net:", "https://[not-an-ip]", "https://", "file:///tmp/server"} {
		if _, err := NormalizeServer(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"https://secrets.example.ts.net", "https://secrets.example.ts.net/", "https://secrets.example.ts.net:8443", "https://[fd7a:115c:a1e0::1]:8443"} {
		if _, err := NormalizeServer(raw); err != nil {
			t.Errorf("rejected %q: %v", raw, err)
		}
	}
}
