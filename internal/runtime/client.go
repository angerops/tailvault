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
	"tailscale.com/ipn/ipnstate"
)

// Identity reads the active local profile on every request. Tagged machines do
// not have a human identity and are not supported by this desktop client.
func Identity(ctx context.Context) (portal.Identity, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var lc local.Client
	s, err := lc.StatusWithoutPeers(ctx)
	return identityFromStatus(s, err)
}

func identityFromStatus(s *ipnstate.Status, err error) (portal.Identity, error) {
	if errors.Is(err, context.DeadlineExceeded) {
		return portal.Identity{}, portal.IdentityError("Tailscale’s local connection did not respond in time. Try again.")
	}
	if err != nil || s == nil {
		return portal.Identity{}, portal.IdentityError("TailVault could not read Tailscale’s local connection. Check that Tailscale is connected, then try again.")
	}
	if s.BackendState != "Running" {
		return portal.Identity{}, portal.IdentityError("Tailscale is disconnected. Connect Tailscale, then try again.")
	}
	if s.Self == nil {
		return portal.Identity{}, portal.IdentityError("Your Tailscale device is not ready. Reconnect Tailscale, then try again.")
	}
	if s.Self.Tags != nil && s.Self.Tags.Len() > 0 {
		return portal.Identity{}, portal.IdentityError("This device is tagged in Tailscale. TailVault needs a device signed in as a user.")
	}
	profile, ok := s.User[s.Self.UserID]
	// The stable ID predates the numeric NodeID field added in Tailscale 1.100.
	if !ok || profile.ID == 0 || profile.ID != s.Self.UserID || s.Self.ID == "" {
		return portal.Identity{}, portal.IdentityError("Your Tailscale user or device could not be identified. Reconnect Tailscale, then try again.")
	}
	var tailnetName, tailnetDNSName string
	if s.CurrentTailnet != nil {
		tailnetName = s.CurrentTailnet.Name
		tailnetDNSName = s.CurrentTailnet.MagicDNSSuffix
	}
	for _, ip := range s.Self.TailscaleIPs {
		if ip.Is4() {
			return portal.Identity{UserID: int64(profile.ID), NodeID: string(s.Self.ID), Name: profile.DisplayName, Login: profile.LoginName, IP: ip.String(), TailnetName: tailnetName, TailnetDNSName: tailnetDNSName}, nil
		}
	}
	return portal.Identity{}, portal.IdentityError("Tailscale has no IPv4 address for this Mac. Check its connection, then try again.")
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
