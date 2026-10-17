package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/angerops/tailvault/internal/portal"
	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
)

func connectedStatus(t *testing.T) *ipnstate.Status {
	t.Helper()
	// Older daemons supply the stable ID but omit the numeric NodeID field.
	var status ipnstate.Status
	if err := json.Unmarshal([]byte(`{
		"BackendState":"Running",
		"Self":{"ID":"n-fixture","UserID":123,"TailscaleIPs":["100.64.0.1"]},
		"User":{"123":{"ID":123,"LoginName":"alice@example.test","DisplayName":"Alice"}},
		"CurrentTailnet":{"Name":"Example team","MagicDNSSuffix":"example.ts.net"}
	}`), &status); err != nil {
		t.Fatal(err)
	}
	return &status
}

func TestIdentityClientReusesConnectionsWithoutCachingStatus(t *testing.T) {
	var status atomic.Pointer[ipnstate.Status]
	status.Store(connectedStatus(t))
	var connections, requests atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/localapi/v0/status" || r.URL.RawQuery != "peers=false" {
			t.Errorf("unexpected status request: %s %s", r.Method, r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status.Load())
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	t.Cleanup(server.Close)
	client := &IdentityClient{client: local.Client{
		OmitAuth: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", server.Listener.Addr().String())
		},
	}}
	for range 100 {
		who, err := client.Identity(t.Context())
		if err != nil || who.UserID != 123 || who.NodeID != "n-fixture" {
			t.Fatalf("identity check failed: %+v, %v", who, err)
		}
	}
	if requests.Load() != 100 || connections.Load() != 1 {
		t.Fatalf("100 identity checks used %d requests and %d connections", requests.Load(), connections.Load())
	}

	next := connectedStatus(t)
	profile := next.User[next.Self.UserID]
	delete(next.User, next.Self.UserID)
	profile.ID = 456
	profile.LoginName = "bob@example.test"
	next.User[profile.ID] = profile
	next.Self.UserID = profile.ID
	next.Self.ID = "n-next"
	status.Store(next)
	who, err := client.Identity(t.Context())
	if err != nil || who.UserID != 456 || who.NodeID != "n-next" || who.Login != "bob@example.test" {
		t.Fatalf("profile change was not observed: %+v, %v", who, err)
	}

	disconnected := connectedStatus(t)
	disconnected.BackendState = "Stopped"
	status.Store(disconnected)
	if who, err := client.Identity(t.Context()); err == nil || who != (portal.Identity{}) {
		t.Fatalf("disconnection returned a stale identity: %+v, %v", who, err)
	}
	status.Store(next)
	server.CloseClientConnections()
	if who, err := client.Identity(t.Context()); err != nil || who.UserID != 456 {
		t.Fatalf("failed to reconnect to the local daemon: %+v, %v", who, err)
	}
	if connections.Load() != 2 {
		t.Fatalf("expected one replacement connection, got %d", connections.Load())
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if who, err := client.Identity(ctx); err == nil || who != (portal.Identity{}) {
		t.Fatalf("canceled check returned an identity: %+v, %v", who, err)
	}
	var checks sync.WaitGroup
	for range 16 {
		checks.Go(func() {
			if who, err := client.Identity(t.Context()); err != nil || who.UserID != 456 {
				t.Errorf("concurrent check failed: %+v, %v", who, err)
			}
		})
	}
	checks.Wait()
	if requests.Load() != 119 {
		t.Fatalf("each check must read fresh status; got %d requests", requests.Load())
	}
}

func TestIdentitySupportsStatusWithoutNumericNodeID(t *testing.T) {
	want := portal.Identity{UserID: 123, NodeID: "n-fixture", Name: "Alice", Login: "alice@example.test", IP: "100.64.0.1", TailnetName: "Example team", TailnetDNSName: "example.ts.net"}
	for _, includeNumericID := range []bool{false, true} {
		s := connectedStatus(t)
		if includeNumericID {
			s.Self.NodeID = 456
		}
		got, err := identityFromStatus(s, nil)
		if err != nil || got != want {
			t.Fatalf("numeric ID present=%v: got %+v, %v", includeNumericID, got, err)
		}
	}
}

func TestIdentityFailuresAreDistinctAndContainNoDaemonDetails(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*ipnstate.Status)
		err   error
		want  string
	}{
		{"local API unavailable", nil, errors.New("synthetic credential marker"), "could not read Tailscale’s local connection"},
		{"timeout", nil, context.DeadlineExceeded, "did not respond in time"},
		{"disconnected", func(s *ipnstate.Status) { s.BackendState = "Stopped" }, nil, "Tailscale is disconnected"},
		{"device missing", func(s *ipnstate.Status) { s.Self = nil }, nil, "device is not ready"},
		{"user missing", func(s *ipnstate.Status) { s.User = nil }, nil, "user or device could not be identified"},
		{"stable ID missing", func(s *ipnstate.Status) { s.Self.ID = "" }, nil, "user or device could not be identified"},
		{"address missing", func(s *ipnstate.Status) { s.Self.TailscaleIPs = nil }, nil, "no IPv4 address"},
		{"tagged", func(s *ipnstate.Status) {
			if err := json.Unmarshal([]byte(`["tag:synthetic"]`), &s.Self.Tags); err != nil {
				t.Fatal(err)
			}
		}, nil, "device is tagged"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := connectedStatus(t)
			if tc.alter != nil {
				tc.alter(s)
			}
			who, err := identityFromStatus(s, tc.err)
			var publicError portal.IdentityError
			if who != (portal.Identity{}) || !errors.As(err, &publicError) || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "synthetic credential marker") {
				t.Fatalf("unexpected identity failure: %+v, %v", who, err)
			}
		})
	}
}

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
	who := portal.Identity{UserID: 123, NodeID: "n-fixture", IP: "127.0.0.1"}
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
