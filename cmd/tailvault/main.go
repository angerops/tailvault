//go:build darwin && cgo

// TailVault runs entirely inside Wails using the active local Tailscale identity.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/angerops/tailvault/internal/portal"
	localruntime "github.com/angerops/tailvault/internal/runtime"
	"github.com/angerops/tailvault/internal/settings"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/menu"
	"github.com/wailsapp/wails/v2/pkg/menu/keys"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

type desktop struct {
	mu      sync.Mutex
	ctx     context.Context
	service *portal.Portal
}

func main() {
	d := &desktop{}
	store, err := settings.DefaultStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "TailVault could not locate its settings:", err)
		return
	}
	saved, loadErr := store.Load()
	var settingsError string
	if loadErr != nil {
		settingsError = "Your saved server settings could not be read. Enter the address again to save a new configuration."
	}
	d.service, err = portal.New(portal.Config{
		Server:         saved.Server,
		SettingsError:  settingsError,
		SaveServer:     store.Save,
		Identity:       localruntime.Identity,
		Command:        localruntime.Command,
		ChooseSavePath: d.chooseSavePath,
		SaveFile:       saveFile,
		CopyText:       func(value string) error { return wailsruntime.ClipboardSetText(d.runtimeContext(), value) },
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "TailVault could not start:", err)
		return
	}
	appMenu := menu.NewMenu()
	appMenu.Append(menu.AppMenu())
	file := appMenu.AddSubmenu("File")
	file.AddText("Settings…", keys.CmdOrCtrl(","), func(*menu.CallbackData) { d.action("settings") })
	file.AddSeparator()
	file.AddText("New Secret", keys.CmdOrCtrl("n"), func(*menu.CallbackData) { d.action("new") })
	file.AddSeparator()
	file.AddText("Hide Vault", keys.Combo("l", keys.CmdOrCtrlKey, keys.ShiftKey), func(*menu.CallbackData) { d.action("lock") })
	appMenu.Append(menu.EditMenu())
	view := appMenu.AddSubmenu("View")
	view.AddText("Search Secrets", keys.CmdOrCtrl("k"), func(*menu.CallbackData) { d.action("search") })
	view.AddText("Refresh Vault", keys.CmdOrCtrl("r"), func(*menu.CallbackData) { d.action("refresh") })
	appMenu.Append(menu.WindowMenu())
	err = wails.Run(&options.App{
		Title: "TailVault", Width: 1280, Height: 840, MinWidth: 860, MinHeight: 620,
		BackgroundColour: options.NewRGB(248, 249, 247), Menu: appMenu,
		AssetServer: &assetserver.Options{Handler: d.service},
		OnStartup:   d.start, OnShutdown: d.stop,
		Mac: &mac.Options{TitleBar: mac.TitleBarDefault(), DisableEscapeExitsFullscreen: true, About: &mac.AboutInfo{Title: "TailVault", Message: "Setec secret manager"}},
		SingleInstanceLock: &options.SingleInstanceLock{UniqueId: "computer.anger.tailvault", OnSecondInstanceLaunch: func(options.SecondInstanceData) {
			d.mu.Lock()
			ctx := d.ctx
			d.mu.Unlock()
			if ctx != nil {
				wailsruntime.WindowShow(ctx)
				wailsruntime.WindowUnminimise(ctx)
			}
		}},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "TailVault could not start:", err)
	}
}

func (d *desktop) start(ctx context.Context) {
	d.mu.Lock()
	d.ctx = ctx
	d.mu.Unlock()
}

func (d *desktop) runtimeContext() context.Context {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ctx
}

func (d *desktop) chooseSavePath(name string) (string, error) {
	ctx := d.runtimeContext()
	name = filepath.Base(name)
	name = strings.Map(func(r rune) rune {
		if strings.ContainsRune(`/:\`, r) {
			return '_'
		}
		return r
	}, name)
	return wailsruntime.SaveFileDialog(ctx, wailsruntime.SaveDialogOptions{Title: "Save secret file", DefaultFilename: name, CanCreateDirectories: true})
}

func saveFile(path string, value []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	if _, err := f.Write(value); err != nil {
		return err
	}
	return f.Close()
}

func (d *desktop) exec(js string) {
	ctx := d.runtimeContext()
	if ctx != nil {
		wailsruntime.WindowExecJS(ctx, fmt.Sprintf("if(location.protocol==='wails:' && location.hostname==='wails'){%s}", js))
	}
}

func (d *desktop) action(action string) {
	d.exec(fmt.Sprintf("window.tailvaultAction?.(%q)", action))
}

func (d *desktop) stop(context.Context) { d.service.Close() }
