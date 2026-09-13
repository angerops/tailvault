package portal

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/angerops/tailvault/internal/settings"
)

// Settings remain available while offline or hidden. Native-origin checks in
// ServeHTTP and a separate revision token protect changes without opening a vault.
func (p *Portal) serverSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.Method == http.MethodPost {
		if !equal(r.Header.Get("X-TailVault-Settings"), p.settingsToken) {
			http.Error(w, "Settings changed. Close and reopen Settings before trying again.", http.StatusConflict)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "request body must be JSON", http.StatusUnsupportedMediaType)
			return
		}
		var input settings.Settings
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "Enter a valid server address.", http.StatusBadRequest)
			return
		}
		server, err := settings.NormalizeServer(input.Server)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if p.cfg.SaveServer == nil || p.cfg.SaveServer(server) != nil {
			http.Error(w, "The server address could not be saved. Check access to TailVault's settings folder and try again.", http.StatusInternalServerError)
			return
		}
		// Each view keeps its original destination. Cancel it before publishing
		// the new server so an old request can never be sent to the new endpoint.
		p.closeViewLocked()
		p.server = server
		p.settingsError = ""
		p.settingsToken = randomToken()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"server": p.server, "settingsToken": p.settingsToken, "error": p.settingsError})
}
