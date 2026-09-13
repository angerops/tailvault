// Package settings stores the user's Setec server address, never secret values.
package settings

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Settings struct {
	Server string `json:"server"`
}

type Store struct{ Path string }

func DefaultStore() (Store, error) {
	dir, err := os.UserConfigDir()
	return Store{Path: filepath.Join(dir, "TailVault", "settings.json")}, err
}

// NormalizeServer accepts an HTTPS origin and an optional trailing slash.
// Credentials, paths, queries, and fragments are never part of the endpoint.
func NormalizeServer(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawPath != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") ||
		strings.ContainsAny(u.Hostname(), " \\%") {
		return "", errors.New("Enter an HTTPS server address without a path, credentials, query, or fragment.")
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", errors.New("Enter a valid server port.")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("Enter a server port between 1 and 65535.")
		}
	}
	if strings.Contains(u.Hostname(), ":") && net.ParseIP(u.Hostname()) == nil {
		return "", errors.New("Enter a valid server address.")
	}
	u.Path = ""
	u.Host = strings.ToLower(u.Host)
	return u.String(), nil
}

func (s Store) Load() (Settings, error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Settings{}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	var saved Settings
	if err := json.Unmarshal(data, &saved); err != nil {
		return Settings{}, err
	}
	server, err := NormalizeServer(saved.Server)
	return Settings{Server: server}, err
}

// Save replaces the settings atomically; a failed save preserves the old file.
func (s Store) Save(raw string) error {
	server, err := NormalizeServer(raw)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(Settings{Server: server}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".settings-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), s.Path)
}
