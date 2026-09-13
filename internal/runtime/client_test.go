package runtime

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/angerops/tailvault/internal/portal"
)

func TestCommandPreservesIdentityAndBytesWithoutForwardingBrowserHeaders(t *testing.T) {
	var path, remote, body string
	var headers http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, remote, headers = r.URL.Path, r.RemoteAddr, r.Header
		data, _ := io.ReadAll(r.Body)
		body = string(data)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"Version":2,"Value":"AP8K"}`)
	}))
	defer server.Close()
	who := portal.Identity{UserID: 123, NodeID: 456, IP: "127.0.0.1"}
	// The test server uses HTTP; startup separately rejects non-HTTPS origins.
	input := `{"Name":"team/../special?name","Value":"AP8K"}`
	result, code, err := Command(context.Background(), who, server.URL, "put", []byte(input))
	if err != nil || code != 200 || string(result) != `{"Version":2,"Value":"AP8K"}` {
		t.Fatal("command response was not preserved")
	}
	if path != "/api/put" || body != input || !strings.HasPrefix(remote, "127.0.0.1:") {
		t.Fatal("incorrect operation, bytes, or source address")
	}
	if headers.Get("Sec-X-Tailscale-No-Browsers") != "setec" || headers.Get("Content-Type") != "application/json" {
		t.Fatal("missing Setec protocol headers")
	}
	for _, name := range []string{"Cookie", "Authorization", "X-TailVault-Connection", "X-Forwarded-For"} {
		if headers.Get(name) != "" {
			t.Fatal("unexpected forwarded credentials or identity")
		}
	}
}

func TestCommandRefusesRedirectsAndUnknownMethods(t *testing.T) {
	var targetCalls int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls++ }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer redirect.Close()
	_, code, err := Command(context.Background(), portal.Identity{IP: "127.0.0.1"}, redirect.URL, "put", []byte(`{"Name":"a","Value":"AA=="}`))
	if err != nil || code != 307 || targetCalls != 0 {
		t.Fatal("redirect was followed")
	}
	if _, _, err := Command(context.Background(), portal.Identity{IP: "127.0.0.1"}, redirect.URL, "../admin", nil); err == nil {
		t.Fatal("unknown operation accepted")
	}
}

func TestValidateServer(t *testing.T) {
	for _, raw := range []string{"http://secrets.example.ts.net", "https://user:pass@secrets.example.ts.net", "https://secrets.example.ts.net/api", "https://secrets.example.ts.net?proxy=true", "https://secrets.example.ts.net#fragment", "file:///tmp/secret"} {
		if ValidateServer(raw) == nil {
			t.Errorf("accepted invalid server %q", raw)
		}
	}
	if ValidateServer("https://secrets.example.ts.net") != nil {
		t.Fatal("valid server rejected")
	}
}
