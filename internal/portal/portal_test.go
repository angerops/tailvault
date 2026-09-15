package portal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type harness struct {
	app           *Portal
	who           Identity
	identityError error
	commandCalls  int
	commandStatus int
	commandBody   []byte
	lastIdentity  Identity
	lastOp        string
	lastServer    string
	lastBody      []byte
	onCommand     func(context.Context)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{who: Identity{UserID: 123, NodeID: "n-fixture", Name: "Alice", Login: "alice@example.test", IP: "100.64.0.1", TailnetName: "Example team", TailnetDNSName: "team.example.ts.net"}, commandStatus: 200, commandBody: []byte(`[]`)}
	var err error
	h.app, err = New(Config{
		Server:         "https://secrets.example.ts.net",
		SaveServer:     func(string) error { return nil },
		ChooseSavePath: func(name string) (string, error) { return name, nil },
		Identity:       func(context.Context) (Identity, error) { return h.who, h.identityError },
		Command: func(ctx context.Context, who Identity, server, op string, body []byte) ([]byte, int, error) {
			h.commandCalls++
			h.lastIdentity = who
			h.lastOp = op
			h.lastServer = server
			h.lastBody = bytes.Clone(body)
			if h.onCommand != nil {
				h.onCommand(ctx)
			}
			return bytes.Clone(h.commandBody), h.commandStatus, ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.app.Close)
	return h
}

func (h *harness) request(method, path, token, body string) *http.Request {
	r := httptest.NewRequest(method, "http://wails"+path, strings.NewReader(body))
	r.Header.Set("Origin", "wails://wails")
	r.Header.Set(connectionHeader, token)
	r.Header.Set("Content-Type", "application/json")
	return r
}
func (h *harness) command(token, op, body string) *http.Request {
	return h.request("POST", "/ui-api/"+op, token, body)
}
func (h *harness) serve(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.app.ServeHTTP(w, r)
	return w
}
func (h *harness) open(t *testing.T) string {
	t.Helper()
	w := h.serve(h.request("GET", "/ui-api/session", "", ""))
	var data struct {
		Connection string `json:"connection"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &data) != nil || data.Connection == "" {
		t.Fatalf("open vault: %d %s", w.Code, w.Body.String())
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("native view must not issue browser cookies")
	}
	return data.Connection
}

func TestNativeViewUsesTailscaleWithoutSignIn(t *testing.T) {
	h := newHarness(t)
	token := h.open(t)
	if h.commandCalls != 0 {
		t.Fatal("opening fetched a secret")
	}
	w := h.serve(h.request("GET", "/ui-api/session", token, ""))
	if !strings.Contains(w.Body.String(), "team.example.ts.net") {
		t.Fatal("missing connected tailnet")
	}
	h.commandBody = []byte(`[{"Name":"alice/key","Versions":[1],"ActiveVersion":1}]`)
	w = h.serve(h.command(token, "list", `{}`))
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), h.commandBody) || !sameIdentity(h.lastIdentity, h.who) {
		t.Fatal("Setec visibility or identity changed")
	}
	for _, path := range []string{"/auth/login", "/auth/callback", "/auth/logout", "/api/get"} {
		if w := h.serve(h.request("GET", path, token, "")); w.Code != 404 {
			t.Fatalf("legacy endpoint available: %s", path)
		}
	}
}

func TestOpeningDisplaysOnlySafeIdentityErrors(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		err  error
		want string
	}{
		{IdentityError("Tailscale is disconnected. Connect Tailscale, then try again."), "Tailscale is disconnected. Connect Tailscale, then try again."},
		{errors.New("synthetic credential marker"), "TailVault could not read Tailscale’s local connection. Check that Tailscale is connected, then try again."},
	} {
		h.identityError = tc.err
		w := h.serve(h.request("GET", "/ui-api/session", "", ""))
		if w.Code != 401 || strings.TrimSpace(w.Body.String()) != tc.want || h.app.view != nil || h.commandCalls != 0 {
			t.Fatalf("incorrect opening error: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestCanceledOpeningCannotReplaceOrRevokeANewerView(t *testing.T) {
	for _, identityError := range []error{nil, errors.New("late identity failure")} {
		h := newHarness(t)
		started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		h.app.cfg.Identity = func(current context.Context) (Identity, error) {
			if current == ctx {
				close(started)
				<-release
				return h.who, identityError
			}
			return h.who, nil
		}
		go func() {
			defer close(finished)
			h.serve(h.request("GET", "/ui-api/session", "", "").WithContext(ctx))
		}()
		<-started
		cancel()
		token := h.open(t)
		close(release)
		<-finished
		if h.app.view == nil || h.app.view.token != token {
			t.Fatal("canceled opening disturbed the later view")
		}
	}
}

func TestNativeRequestsRejectForeignOriginsAndStaleViews(t *testing.T) {
	h := newHarness(t)
	token := h.open(t)
	for _, test := range []struct {
		alter func(*http.Request)
		code  int
	}{
		{func(r *http.Request) { r.Host = "127.0.0.1:8765" }, 421},
		{func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, 403},
		{func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		{func(r *http.Request) { r.Header.Del(connectionHeader) }, 401},
		{func(r *http.Request) { r.Header.Set(connectionHeader, "old-view") }, 401},
		{func(r *http.Request) { r.Method = "GET" }, 405},
		{func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415},
		{func(r *http.Request) { r.URL.Path = "/ui-api/admin" }, 404},
		{func(r *http.Request) { r.Body = http.NoBody }, 400},
	} {
		r := h.command(token, "list", `{}`)
		test.alter(r)
		if w := h.serve(r); w.Code != test.code {
			t.Fatalf("HTTP %d, want %d", w.Code, test.code)
		}
	}
	if h.commandCalls != 0 {
		t.Fatal("rejected native request reached Setec")
	}
}

func TestIdentityChangeOfflineAndHideRevokeTheView(t *testing.T) {
	for _, mode := range []string{"user", "node", "ip", "tailnet", "offline", "hide"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t)
			token := h.open(t)
			switch mode {
			case "user":
				h.who.UserID++
			case "node":
				h.who.NodeID = "n-replacement"
			case "ip":
				h.who.IP = "100.64.0.2"
			case "tailnet":
				h.who.TailnetDNSName = "other.example.ts.net"
			case "offline":
				h.identityError = errors.New("offline")
			case "hide":
				if w := h.serve(h.command(token, "close", `{}`)); w.Code != 204 {
					t.Fatal("hide failed")
				}
			}
			if w := h.serve(h.command(token, "get", `{"Name":"alice/key"}`)); w.Code != 401 {
				t.Fatal("stale view retained access")
			}
			if h.commandCalls != 0 || h.app.view != nil {
				t.Fatal("stale view not revoked")
			}
			h.identityError = nil
			fresh := h.open(t)
			if fresh == token {
				t.Fatal("reopened view reused its old handle")
			}
			if w := h.serve(h.command(token, "get", `{"Name":"alice/key"}`)); w.Code != 401 {
				t.Fatal("old view replay accepted")
			}
		})
	}
}

func TestOfflineStartupCanReconnect(t *testing.T) {
	h := newHarness(t)
	h.identityError = errors.New("offline")
	if w := h.serve(h.request("GET", "/ui-api/session", "", "")); w.Code != 401 {
		t.Fatal("offline view opened")
	}
	h.identityError = nil
	h.open(t)
	if h.commandCalls != 0 {
		t.Fatal("reconnect fetched a secret")
	}
}

func TestHideCancelsInFlightFetches(t *testing.T) {
	h := newHarness(t)
	token := h.open(t)
	started := make(chan struct{})
	done := make(chan *httptest.ResponseRecorder, 1)
	h.onCommand = func(ctx context.Context) { close(started); <-ctx.Done() }
	go func() { done <- h.serve(h.command(token, "get", `{"Name":"alice/key"}`)) }()
	<-started
	h.app.Close()
	select {
	case w := <-done:
		if w.Code != 401 {
			t.Fatalf("hidden result returned %d", w.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("hide did not cancel the fetch")
	}
}

func TestIdentitySwitchDuringFetchDiscardsValue(t *testing.T) {
	for _, op := range []string{"get", "copy", "download"} {
		h := newHarness(t)
		token := h.open(t)
		effects := 0
		h.app.cfg.CopyText = func(string) error { effects++; return nil }
		h.app.cfg.SaveFile = func(string, []byte) error { effects++; return nil }
		h.commandBody = []byte(`{"Value":"cHJpdmF0ZS12YWx1ZQ==","Version":1}`)
		h.onCommand = func(context.Context) { h.who.UserID++ }
		w := h.serve(h.command(token, op, `{"Name":"alice/key"}`))
		if w.Code != 401 || effects != 0 || strings.Contains(w.Body.String(), "cHJpdmF0ZS12YWx1ZQ") {
			t.Fatalf("identity change exposed %s result", op)
		}
	}
}

func TestSetecPermissionsAndUploadLimits(t *testing.T) {
	h := newHarness(t)
	token := h.open(t)
	h.commandStatus = 403
	h.commandBody = []byte("private upstream detail")
	for _, op := range []string{"get", "info", "put", "create-version", "activate", "delete", "delete-version"} {
		w := h.serve(h.command(token, op, `{"Name":"bob/key","Value":"AA=="}`))
		if w.Code != 403 || strings.Contains(w.Body.String(), "upstream detail") {
			t.Fatal("Setec denial was not preserved safely")
		}
	}
	calls := h.commandCalls
	large, _ := json.Marshal(map[string]any{"Name": "alice/large", "Value": make([]byte, (1<<20)+1)})
	for _, test := range []struct {
		body string
		code int
	}{
		{string(large), 413}, {strings.Repeat("x", maxBody+1), 413}, {`{"Name":"a","Value":"invalid base64"}`, 400},
	} {
		if w := h.serve(h.command(token, "put", test.body)); w.Code != test.code {
			t.Fatalf("upload status %d", w.Code)
		}
	}
	if h.commandCalls != calls {
		t.Fatal("invalid upload reached Setec")
	}
}

func TestNativeCopyAndSavePreservePermissionsAndBytes(t *testing.T) {
	h := newHarness(t)
	token := h.open(t)
	saved, copied := 0, 0
	h.app.cfg.SaveFile = func(name string, value []byte) error {
		saved++
		if name != "alice/file" || !bytes.Equal(value, []byte{0, 255, 10}) {
			t.Fatal("export changed bytes")
		}
		return nil
	}
	h.app.cfg.CopyText = func(string) error { copied++; return nil }
	h.commandStatus = 403
	if w := h.serve(h.command(token, "download", `{"Name":"alice/file"}`)); w.Code != 403 || saved != 0 {
		t.Fatal("save bypassed permission denial")
	}
	h.commandStatus = 200
	h.commandBody = []byte(`{"Value":"AP8K","Version":1}`)
	if w := h.serve(h.command(token, "download", `{"Name":"alice/file"}`)); w.Code != 200 || saved != 1 || h.lastOp != "get" {
		t.Fatal("native export failed")
	}
	if w := h.serve(h.command(token, "copy", `{"Name":"alice/file"}`)); w.Code != 400 || copied != 0 {
		t.Fatal("binary clipboard accepted")
	}
	h.commandBody = []byte(`{"Value":"dGVzdA==","Version":1}`)
	if w := h.serve(h.command(token, "copy", `{"Name":"alice/file"}`)); w.Code != 204 || copied != 1 {
		t.Fatal("native copy failed")
	}
}

func TestNativeAssetsKeepBrowserProtections(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/", "/app.js", "/style.css", "/icon.svg"} {
		w := h.serve(h.request("GET", path, "", ""))
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatalf("asset protection missing: %s", path)
		}
	}
}

// EXPORT-1: revocation happens while the user is considering the native dialog,
// after the upstream value has arrived but before a local write is allowed.
func TestPendingSaveRevalidatesAfterDialog(t *testing.T) {
	for _, reason := range []string{"hide", "shutdown", "identity", "settings", "cancel"} {
		t.Run(reason, func(t *testing.T) {
			h := newHarness(t)
			token := h.open(t)
			h.commandBody = []byte(`{"Value":"c3ludGhldGlj","Version":1}`)
			entered, proceed := make(chan struct{}), make(chan struct{})
			h.app.cfg.ChooseSavePath = func(string) (string, error) {
				close(entered)
				<-proceed
				if reason == "cancel" {
					return "", nil
				}
				return "user-selected-path", nil
			}
			writes := 0
			h.app.cfg.SaveFile = func(string, []byte) error { writes++; return nil }
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- h.serve(h.command(token, "download", `{"Name":"audit/secret"}`)) }()
			<-entered
			switch reason {
			case "hide":
				if w := h.serve(h.command(token, "close", `{}`)); w.Code != 204 {
					t.Fatal("hide blocked by dialog")
				}
			case "shutdown":
				h.app.Close()
			case "identity":
				h.who.UserID++
			case "settings":
				if w := h.serve(h.settingsRequest(h.app.settingsToken, "https://new.example.ts.net")); w.Code != 200 {
					t.Fatal("settings blocked by dialog")
				}
			}
			close(proceed)
			w := <-done
			want := 401
			if reason == "cancel" {
				want = 200
			}
			if w.Code != want || writes != 0 {
				t.Fatalf("status=%d, writes=%d", w.Code, writes)
			}
			if reason == "cancel" && !strings.Contains(w.Body.String(), `"saved":false`) {
				t.Fatal("cancel reported as saved")
			}
		})
	}
}
