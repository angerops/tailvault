package runtime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/angerops/tailvault/internal/portal"
	"github.com/angerops/tailvault/internal/settings"
	"tailscale.com/client/local"
)

// Identity reads the active local profile on every request. Tagged machines do
// not have a human identity and are not supported by this desktop client.
func Identity(ctx context.Context) (portal.Identity, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var lc local.Client
	s, err := lc.StatusWithoutPeers(ctx)
	if err != nil || s == nil || s.BackendState != "Running" || s.Self == nil {
		return portal.Identity{}, errors.New("Tailscale must be running")
	}
	if s.Self.Tags != nil && s.Self.Tags.Len() > 0 {
		return portal.Identity{}, errors.New("sign in to Tailscale as a user; tagged nodes are not supported")
	}
	profile, ok := s.User[s.Self.UserID]
	if !ok || profile.ID == 0 || s.Self.NodeID == 0 {
		return portal.Identity{}, errors.New("active Tailscale user could not be identified")
	}
	var tailnetName, tailnetDNSName string
	if s.CurrentTailnet != nil {
		tailnetName = s.CurrentTailnet.Name
		tailnetDNSName = s.CurrentTailnet.MagicDNSSuffix
	}
	for _, ip := range s.Self.TailscaleIPs {
		if ip.Is4() {
			return portal.Identity{UserID: int64(profile.ID), NodeID: int64(s.Self.NodeID), Name: profile.DisplayName, Login: profile.LoginName, IP: ip.String(), TailnetName: tailnetName, TailnetDNSName: tailnetDNSName}, nil
		}
	}
	return portal.Identity{}, errors.New("no local Tailscale IPv4 address is available")
}

func ValidateServer(raw string) error {
	_, err := settings.NormalizeServer(raw)
	return err
}

// DirectClient disables environment proxies and redirects so secret values
// are never forwarded to another origin.
func DirectClient() *http.Client {
	return &http.Client{
		Timeout:       20 * time.Second,
		Transport:     &http.Transport{Proxy: nil, TLSHandshakeTimeout: 10 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func Command(ctx context.Context, who portal.Identity, server, op string, body []byte) ([]byte, int, error) {
	// The portal selects op from a fixed allowlist. Retain that boundary here.
	switch op {
	case "list", "get", "info", "put", "create-version", "activate", "delete", "delete-version":
	default:
		return nil, 0, errors.New("unsupported operation")
	}
	ip := net.ParseIP(who.IP)
	if ip == nil {
		return nil, 0, errors.New("missing local identity address")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, LocalAddr: &net.TCPAddr{IP: ip}}
	client := DirectClient()
	transport := client.Transport.(*http.Transport)
	transport.DialContext = dialer.DialContext
	// Do not reuse a connection across local Tailscale profile changes.
	transport.DisableKeepAlives = true
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/api/"+op, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-X-Tailscale-No-Browsers", "setec")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	result, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil || len(result) > 2<<20 {
		return nil, 0, errors.New("Setec response exceeds the size limit")
	}
	return result, resp.StatusCode, nil
}
