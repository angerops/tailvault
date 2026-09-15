package provider_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/angerops/tailvault/internal/portal"
	appRuntime "github.com/angerops/tailvault/internal/runtime"
	"github.com/tailscale/setec/server"
	"github.com/tailscale/setec/setectest"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// These same cases exercise tests/preview.mjs. Only the network and WhoIs are
// substituted: all requests pass through the real portal, transport and Setec DB.
func TestProviderContract(t *testing.T) {
	raw, err := os.ReadFile("../setec-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Label  string
		Op     string
		Body   json.RawMessage
		Status int
		Result json.RawMessage
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	db := setectest.NewDB(t, nil)
	db.MustPut(db.Superuser, "finance/hidden", "synthetic denied value")
	db.MustPut(db.Superuser, "finance/private/password", "x")
	ss := setectest.NewServer(t, db, &setectest.ServerOptions{WhoIs: func(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
		who, err := setectest.AllAccess(ctx, addr)
		// Permission is decided by the actual server, including filtering list.
		who.CapMap[server.ACLCap] = []tailcfg.RawMessage{
			`{"action":["info","get","put","create-version","activate","delete"],"secret":["personal/*"]}`,
			`{"action":["info"],"secret":["finance/private/*"]}`,
		}
		return who, err
	}})
	hs := httptest.NewServer(ss.Mux)
	defer hs.Close()
	who := portal.Identity{UserID: 1, NodeID: "n-fixture", IP: "127.0.0.1", Login: "synthetic@example.test"}
	app, err := portal.New(portal.Config{
		Server:   "https://secrets.example.ts.net",
		Identity: func(context.Context) (portal.Identity, error) { return who, nil },
		Command: func(ctx context.Context, identity portal.Identity, _, op string, body []byte) ([]byte, int, error) {
			return appRuntime.Command(ctx, identity, hs.URL, op, body)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	token := ""
	request := func(method, op string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://wails/ui-api/"+op, bytes.NewReader(body))
		req.Header.Set("Origin", "wails://wails")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-TailVault-Connection", token)
		res := httptest.NewRecorder()
		app.ServeHTTP(res, req)
		return res
	}
	res := request("GET", "session", nil)
	var session struct{ Connection string }
	if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &session) != nil || session.Connection == "" {
		t.Fatal("cannot open synthetic view")
	}
	token = session.Connection
	for _, tc := range cases {
		t.Run(tc.Label, func(t *testing.T) {
			res := request("POST", tc.Op, tc.Body)
			if res.Code != tc.Status {
				t.Fatalf("status %d, want %d: %s", res.Code, tc.Status, res.Body.String())
			}
			if tc.Result != nil {
				var got, want any
				if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(tc.Result, &want); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("got %s; want %s", res.Body.Bytes(), tc.Result)
				}
			}
		})
	}
}
