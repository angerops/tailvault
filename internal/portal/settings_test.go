package portal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func (h *harness) settingsRequest(token, server string) *http.Request {
	body, _ := json.Marshal(map[string]string{"server": server})
	r := h.request("POST", "/ui-api/settings", "", string(body))
	r.Header.Set("X-TailVault-Settings", token)
	return r
}

func TestFirstRunSettingsWorkWithoutTailscale(t *testing.T) {
	h := newHarness(t)
	h.app.server = ""
	h.identityError = errors.New("offline")
	w := h.serve(h.request("GET", "/ui-api/settings", "", ""))
	var data struct {
		Server string `json:"server"`
		Token  string `json:"settingsToken"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &data) != nil || data.Server != "" || data.Token == "" {
		t.Fatalf("first-run settings: %d %s", w.Code, w.Body.String())
	}
	if w := h.serve(h.request("GET", "/ui-api/session", "", "")); w.Code != 428 {
		t.Fatal("unconfigured vault opened")
	}
	var saved string
	h.app.cfg.SaveServer = func(server string) error { saved = server; return nil }
	w = h.serve(h.settingsRequest(data.Token, " https://new.example.ts.net/ "))
	if w.Code != 200 || saved != "https://new.example.ts.net" || h.commandCalls != 0 {
		t.Fatalf("offline configuration failed: %d %s", w.Code, w.Body.String())
	}
	if w := h.serve(h.request("GET", "/ui-api/session", "", "")); w.Code != 401 {
		t.Fatal("server configuration bypassed Tailscale")
	}
	h.identityError = nil
	token := h.open(t)
	w = h.serve(h.command(token, "list", `{}`))
	if w.Code != 200 || h.lastServer != saved {
		t.Fatal("the configured server was not used")
	}
}

func TestSettingsRejectForeignStaleAndInvalidWrites(t *testing.T) {
	h := newHarness(t)
	token := h.app.settingsToken
	saves := 0
	h.app.cfg.SaveServer = func(string) error { saves++; return nil }
	for _, test := range []struct {
		alter func(*http.Request)
		code  int
	}{
		{func(r *http.Request) { r.Host = "evil.example" }, 421},
		{func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, 403},
		{func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		{func(r *http.Request) { r.Header.Del("X-TailVault-Settings") }, 409},
		{func(r *http.Request) { r.Method = "PUT" }, 405},
		{func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415},
		{func(r *http.Request) { r.Body = http.NoBody }, 400},
	} {
		r := h.settingsRequest(token, "https://new.example.ts.net")
		test.alter(r)
		if w := h.serve(r); w.Code != test.code {
			t.Fatalf("settings returned %d, want %d", w.Code, test.code)
		}
	}
	for _, body := range []string{`{"server":"http://insecure.example"}`, `{"server":"https://new.example.ts.net","unexpected":true}`, `{"server":"https://new.example.ts.net"} {}`, strings.Repeat("x", 4097)} {
		r := h.request("POST", "/ui-api/settings", "", body)
		r.Header.Set("X-TailVault-Settings", token)
		if w := h.serve(r); w.Code != 400 {
			t.Fatalf("invalid settings returned %d", w.Code)
		}
	}
	if saves != 0 {
		t.Fatal("rejected settings were persisted")
	}
	if w := h.serve(h.settingsRequest(token, "https://new.example.ts.net")); w.Code != 200 {
		t.Fatal("valid settings failed")
	}
	if w := h.serve(h.settingsRequest(token, "https://stale.example.ts.net")); w.Code != 409 || saves != 1 {
		t.Fatal("stale settings overwrote the new address")
	}
}

func TestFailedSettingsSaveKeepsPreviousServerAndView(t *testing.T) {
	h := newHarness(t)
	token := h.open(t)
	h.app.cfg.SaveServer = func(string) error { return errors.New("disk full") }
	if w := h.serve(h.settingsRequest(h.app.settingsToken, "https://new.example.ts.net")); w.Code != 500 {
		t.Fatal("failed disk write was reported as saved")
	}
	if w := h.serve(h.command(token, "list", `{}`)); w.Code != 200 || h.lastServer != "https://secrets.example.ts.net" {
		t.Fatal("failed save changed the active connection")
	}
}

func TestServerChangeCancelsOldRequestsAndUpdatesCurl(t *testing.T) {
	for _, op := range []string{"get", "copy", "download"} {
		t.Run(op, func(t *testing.T) {
			h := newHarness(t)
			token := h.open(t)
			effects := 0
			h.app.cfg.CopyText = func(string) error { effects++; return nil }
			h.app.cfg.SaveFile = func(string, []byte) error { effects++; return nil }
			h.commandBody = []byte(`{"Value":"cHJpdmF0ZQ==","Version":1}`)
			started := make(chan struct{})
			done := make(chan *httptest.ResponseRecorder, 1)
			h.onCommand = func(ctx context.Context) { close(started); <-ctx.Done() }
			go func() { done <- h.serve(h.command(token, op, `{"Name":"alice/key"}`)) }()
			<-started
			w := h.serve(h.settingsRequest(h.app.settingsToken, "https://new.example.ts.net"))
			if w.Code != 200 {
				t.Fatalf("save: %d %s", w.Code, w.Body.String())
			}
			select {
			case w := <-done:
				if w.Code != 401 || strings.Contains(w.Body.String(), "cHJpdmF0ZQ") || effects != 0 || h.lastServer != "https://secrets.example.ts.net" {
					t.Fatal("old request was exposed or sent to the new server")
				}
			case <-time.After(time.Second):
				t.Fatal("server change did not cancel the pending request")
			}
			h.onCommand = nil
			h.commandBody = []byte(`[]`) // The new list request returns metadata, not the canceled value.
			fresh := h.open(t)
			if w := h.serve(h.command(token, "put", `{"Name":"alice/key","Value":"AA=="}`)); w.Code != 401 {
				t.Fatal("old view could write to the new server")
			}
			if w := h.serve(h.command(fresh, "list", `{}`)); w.Code != 200 || h.lastServer != "https://new.example.ts.net" {
				t.Fatal("new view did not use the saved server")
			}
			w = h.serve(h.command(fresh, "curl", `{"Name":"alice/key"}`))
			if w.Code != 200 || !strings.Contains(w.Body.String(), "https://new.example.ts.net/api/get") {
				t.Fatal("curl retained the old server address")
			}
		})
	}
}
