// Package portal serves Setec through Wails's in-process asset handler.
// It does not listen on a network socket or perform a separate user sign-in.
package portal

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/angerops/tailvault/internal/settings"
)

//go:embed assets/*
var assets embed.FS

const maxBody = 2 << 20
const connectionHeader = "X-TailVault-Connection"

// Identity is supplied by the local Tailscale daemon, never by the UI.
type Identity struct {
	UserID, NodeID              int64
	Name, Login, IP             string
	TailnetName, TailnetDNSName string
}

type Config struct {
	Server         string
	SettingsError  string
	SaveServer     func(string) error
	Identity       func(context.Context) (Identity, error)
	Command        func(context.Context, Identity, string, string, []byte) ([]byte, int, error)
	SaveFile       func(string, []byte) error
	ChooseSavePath func(string) (string, error)
	CopyText       func(string) error
}

// A view binds in-flight actions to the identity displayed by the UI. The
// opaque handle is an in-memory request guard, not an authentication credential.
type view struct {
	who    Identity
	server string
	token  string
	ctx    context.Context
	cancel context.CancelFunc
}

type Portal struct {
	cfg           Config
	mu            sync.Mutex
	view          *view
	server        string
	settingsToken string
	settingsError string
	static        http.Handler
}

func New(cfg Config) (*Portal, error) {
	if cfg.Server != "" {
		server, err := settings.NormalizeServer(cfg.Server)
		if err != nil {
			return nil, err
		}
		cfg.Server = server
	}
	if cfg.Identity == nil || cfg.Command == nil {
		return nil, errors.New("local identity and Setec client are required")
	}
	static, _ := fs.Sub(assets, "assets")
	return &Portal{cfg: cfg, server: cfg.Server, settingsToken: randomToken(), settingsError: cfg.SettingsError, static: http.FileServer(http.FS(static))}, nil
}

func (p *Portal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' wails:; style-src 'self' wails:; img-src 'self' wails: data:; connect-src 'self' wails:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	// Wails validates the custom-protocol host before invoking this handler.
	// Opaque WebKit custom-scheme requests may serialize their origin as null.
	if r.Host != "wails" {
		http.Error(w, "native app requests only", http.StatusMisdirectedRequest)
		return
	}
	origin := r.Header.Get("Origin")
	site := r.Header.Get("Sec-Fetch-Site")
	if (origin != "" && origin != "wails://wails" && origin != "null") || (site != "" && site != "same-origin" && site != "none") {
		http.Error(w, "Request origin could not be verified.", http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/ui-api/settings":
		p.serverSettings(w, r)
	case "/ui-api/session":
		p.sessionInfo(w, r)
	case "/ui-api/status":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		if _, _, ok := p.authenticate(w, r); ok {
			w.WriteHeader(http.StatusNoContent)
		}
	case "/ui-api/close":
		if !nativePOST(w, r) {
			return
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.view == nil || !equal(r.Header.Get(connectionHeader), p.view.token) {
			http.Error(w, "This view is no longer active.", http.StatusUnauthorized)
			return
		}
		p.closeViewLocked()
		w.WriteHeader(http.StatusNoContent)
	case "/", "/app.js", "/style.css", "/icon.svg":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", 405)
			return
		}
		p.static.ServeHTTP(w, r)
	default:
		if strings.HasPrefix(r.URL.Path, "/ui-api/") {
			p.command(w, r)
			return
		}
		http.NotFound(w, r)
	}
}

func (p *Portal) peer(ctx context.Context) (Identity, error) {
	who, err := p.cfg.Identity(ctx)
	if err != nil || who.UserID == 0 || who.NodeID == 0 || who.IP == "" {
		return Identity{}, errors.New("Connect Tailscale with a user-owned device, then open the vault.")
	}
	return who, nil
}

func sameIdentity(a, b Identity) bool {
	return a.UserID == b.UserID && a.NodeID == b.NodeID && a.IP == b.IP && a.TailnetName == b.TailnetName && a.TailnetDNSName == b.TailnetDNSName
}

func (p *Portal) sessionInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	who, err := p.peer(r.Context())
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.server == "" {
		http.Error(w, "Set up your Setec server to open the vault.", http.StatusPreconditionRequired)
		return
	}
	if err != nil {
		p.closeViewLocked()
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if p.view != nil && !sameIdentity(who, p.view.who) {
		p.closeViewLocked()
		http.Error(w, "Tailscale identity changed. Open the vault to use the current connection.", http.StatusUnauthorized)
		return
	}
	if p.view == nil {
		ctx, cancel := context.WithCancel(context.Background())
		p.view = &view{who: who, server: p.server, token: randomToken(), ctx: ctx, cancel: cancel}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"name": who.Name, "login": who.Login, "tailnet": map[string]string{"name": who.TailnetName, "dnsName": who.TailnetDNSName}, "server": p.view.server, "connection": p.view.token})
}

func (p *Portal) authenticate(w http.ResponseWriter, r *http.Request) (*view, Identity, bool) {
	p.mu.Lock()
	s := p.view
	p.mu.Unlock()
	if s == nil || !equal(r.Header.Get(connectionHeader), s.token) {
		http.Error(w, "This view is no longer active. Open the vault again.", http.StatusUnauthorized)
		return nil, Identity{}, false
	}
	who, err := p.peer(r.Context())
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.view != s || err != nil || !sameIdentity(who, s.who) {
		if p.view == s {
			p.closeViewLocked()
		}
		http.Error(w, "Tailscale disconnected or its identity changed. Open the vault to reconnect.", http.StatusUnauthorized)
		return nil, Identity{}, false
	}
	return s, who, true
}

func nativePOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST requests allowed", 405)
		return false
	}
	return true
}

func (p *Portal) closeViewLocked() {
	if p.view != nil {
		p.view.cancel()
		p.view = nil
	}
}

func (p *Portal) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeViewLocked()
}

var errInactiveView = errors.New("the vault view is no longer active")

// runEffect revalidates after any native dialog, then orders the short local
// effect against Close/settings changes. Never hold mu while displaying a dialog.
func (p *Portal) runEffect(ctx context.Context, s *view, effect func() error) error {
	who, err := p.peer(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.view != s || s.ctx.Err() != nil || ctx.Err() != nil || err != nil || !sameIdentity(who, s.who) {
		if p.view == s {
			p.closeViewLocked()
		}
		return errInactiveView
	}
	return effect()
}

func nativeError(w http.ResponseWriter, err error) {
	if errors.Is(err, errInactiveView) {
		http.Error(w, "This view is no longer active. Open the vault again.", http.StatusUnauthorized)
		return
	}
	http.Error(w, "The file or clipboard operation could not be completed.", http.StatusInternalServerError)
}

func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("system random source unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func equal(a, b string) bool { return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (p *Portal) command(w http.ResponseWriter, r *http.Request) {
	op := strings.TrimPrefix(r.URL.Path, "/ui-api/")
	switch op {
	case "list", "get", "info", "put", "create-version", "activate", "delete", "delete-version":
	case "curl":
	case "copy-curl":
		if p.cfg.CopyText == nil {
			http.NotFound(w, r)
			return
		}
	case "download":
		if p.cfg.SaveFile == nil || p.cfg.ChooseSavePath == nil {
			http.NotFound(w, r)
			return
		}
	case "copy", "copy-path":
		if p.cfg.CopyText == nil {
			http.NotFound(w, r)
			return
		}
	default:
		http.NotFound(w, r)
		return
	}
	if !nativePOST(w, r) {
		return
	}
	s, who, ok := p.authenticate(w, r)
	if !ok {
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "request body must be JSON", http.StatusUnsupportedMediaType)
		return
	}
	if r.ContentLength > maxBody {
		http.Error(w, "Secret exceeds the upload limit.", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Secret exceeds the upload limit.", http.StatusRequestEntityTooLarge)
		return
	}
	if !json.Valid(body) {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if op == "curl" || op == "copy-curl" {
		var input struct {
			Name    string
			Version uint32
			Decode  bool
		}
		if json.Unmarshal(body, &input) != nil || input.Name == "" {
			http.Error(w, "a secret path and valid version are required", http.StatusBadRequest)
			return
		}
		command := curlCommand(s.server, curlRequest{Name: input.Name, Version: input.Version, Decode: input.Decode})
		if op == "copy-curl" {
			if err := p.runEffect(r.Context(), s, func() error { return p.cfg.CopyText(command) }); err != nil {
				nativeError(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"command": command})
		}
		return
	}
	if op == "put" || op == "create-version" {
		var value struct {
			Name  string
			Value []byte
		}
		if json.Unmarshal(body, &value) != nil || value.Name == "" {
			http.Error(w, "a secret name and base64 value are required", http.StatusBadRequest)
			return
		}
		if len(value.Value) > 1<<20 {
			http.Error(w, "Secret exceeds the 1 MiB upload limit.", http.StatusRequestEntityTooLarge)
			return
		}
	}
	upstreamOp := op
	if op == "download" || op == "copy" {
		upstreamOp = "get"
	}
	if op == "copy-path" {
		var input struct{ Name string }
		if json.Unmarshal(body, &input) != nil || input.Name == "" {
			http.Error(w, "a path is required", 400)
			return
		}
		if err := p.runEffect(r.Context(), s, func() error { return p.cfg.CopyText(input.Name) }); err != nil {
			nativeError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(s.ctx, cancel)
	defer cancel()
	defer stop()
	if err := s.ctx.Err(); err != nil {
		http.Error(w, "This view is no longer active. Open the vault again.", http.StatusUnauthorized)
		return
	}
	result, code, err := p.cfg.Command(ctx, who, s.server, upstreamOp, body)
	defer clear(result)
	// Discard an in-flight result if the view closed or Tailscale switched profiles.
	if _, _, ok := p.authenticate(w, r); !ok {
		return
	}
	if err != nil {
		http.Error(w, "Setec could not be reached. Check Tailscale and your server address.", http.StatusBadGateway)
		return
	}
	if code >= 200 && code < 300 {
		if op == "list" || op == "info" {
			metadata, err := sanitizeMetadata(op, result)
			if err != nil {
				http.Error(w, "Setec returned invalid secret metadata.", http.StatusBadGateway)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			w.Write(metadata)
			return
		}
		if op == "download" || op == "copy" {
			var value struct {
				Value   []byte
				Version uint32
			}
			var input struct{ Name string }
			if json.Unmarshal(result, &value) != nil || value.Version == 0 || json.Unmarshal(body, &input) != nil {
				http.Error(w, "Invalid Setec response.", 502)
				return
			}
			if op == "copy" && (!utf8.Valid(value.Value) || strings.ContainsRune(string(value.Value), 0)) {
				clear(value.Value)
				http.Error(w, "This is a binary secret. Use Download to preserve its bytes.", http.StatusBadRequest)
				return
			}
			if op == "download" {
				path, dialogErr := p.cfg.ChooseSavePath(input.Name)
				err = p.runEffect(ctx, s, func() error {
					if dialogErr != nil || path == "" {
						return dialogErr
					}
					return p.cfg.SaveFile(path, value.Value)
				})
				clear(value.Value)
				if err != nil {
					nativeError(w, err)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]bool{"saved": path != ""})
				return
			} else {
				err = p.runEffect(ctx, s, func() error { return p.cfg.CopyText(string(value.Value)) })
			}
			clear(value.Value)
			if err != nil {
				nativeError(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		w.Write(result)
		return
	}
	// Never reflect an upstream HTML page, error, or secret in an error response.
	switch code {
	case http.StatusForbidden:
		http.Error(w, "Your Tailscale permissions do not allow this action on this path.", code)
	case http.StatusNotFound:
		http.Error(w, "Secret or version is unavailable.", code)
	case http.StatusPreconditionFailed:
		http.Error(w, "This version number has already been used.", code)
	case http.StatusBadRequest:
		http.Error(w, "Setec rejected the request. Check the secret and version.", code)
	default:
		http.Error(w, "Setec could not complete the action. Refresh before retrying.", http.StatusBadGateway)
	}

}
