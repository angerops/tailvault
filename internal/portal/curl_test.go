package portal

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestCurlCommandsPreserveShellArguments(t *testing.T) {
	for _, shell := range []string{"sh", "bash", "zsh"} {
		t.Run(shell, func(t *testing.T) {
			path, err := exec.LookPath(shell)
			if err != nil {
				t.Skipf("%s is not installed", shell)
			}
			for _, name := range []string{
				"personal/service/key",
				"personal/it's a key with spaces",
				"personal/'; touch injected; #$(touch injected)`touch injected`\"\\\n雪\t<&>",
				"-option/@file\x00end",
			} {
				for _, version := range []uint32{0, 42, 4294967295} {
					command := curlCommand("https://secrets.example.ts.net", curlRequest{Name: name, Version: version})
					// Stub curl so the generated command is parsed by a real shell
					// but can never contact Setec or any other network endpoint.
					cmd := exec.Command(path, "-c", "curl() { printf '%s\\000' \"$@\"; };\n"+command)
					cmd.Dir = t.TempDir()
					output, err := cmd.CombinedOutput()
					if err != nil {
						t.Fatalf("shell rejected command: %v: %s", err, output)
					}
					args := strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00")
					want := []string{"--disable", "--fail", "--silent", "--show-error", "--noproxy", "*", "--request", "POST", "--header", "Sec-X-Tailscale-No-Browsers: setec", "--header", "Content-Type: application/json", "--data-raw"}
					if len(args) != len(want)+2 || !reflect.DeepEqual(args[:len(want)], want) || args[len(args)-1] != "https://secrets.example.ts.net/api/get" {
						t.Fatalf("unexpected shell arguments: %q", args)
					}
					var body map[string]any
					if err := json.Unmarshal([]byte(args[len(want)]), &body); err != nil || body["Name"] != name {
						t.Fatalf("path changed in shell: %v, %v", body, err)
					}
					if version == 0 {
						if len(body) != 1 {
							t.Fatal("active-version command should only contain Name")
						}
					} else if len(body) != 2 || body["Version"] != float64(version) {
						t.Fatal("explicit version was not preserved")
					}
					files, err := os.ReadDir(cmd.Dir)
					if err != nil || len(files) != 0 {
						t.Fatal("shell executed text from the secret path")
					}
				}
			}
		})
	}
}

func TestCurlDecoderPreservesBytesAndReportsFailure(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("Python 3 is required to exercise the optional decoder")
	}
	command := curlCommand("https://secrets.example.ts.net", curlRequest{Name: "personal/key", Decode: true})
	for _, value := range [][]byte{[]byte("sample value\n\n"), {0, 255, 254, 13, 10, 0, 128}, {}} {
		body, _ := json.Marshal(map[string]any{"Value": value, "Version": 2})
		cmd := exec.Command("sh", "-c", "curl() { printf '%s' \"$TAILVAULT_TEST_RESPONSE\"; };\n"+command)
		cmd.Env = append(os.Environ(), "TAILVAULT_TEST_RESPONSE="+string(body))
		output, err := cmd.Output()
		if err != nil || !bytes.Equal(output, value) {
			t.Fatalf("decoder changed bytes: %x, %v", output, err)
		}
	}
	cmd := exec.Command("sh", "-c", "curl() { return 22; };\n"+command)
	if output, err := cmd.Output(); err == nil || len(output) != 0 {
		t.Fatal("failed fetch must fail without emitting a value")
	}
}

func TestCurlEndpointsUseMetadataOnly(t *testing.T) {
	h := newHarness(t)
	var copied string
	h.app.cfg.CopyText = func(value string) error { copied = value; return nil }
	token := h.open(t)
	body := `{"Name":"alice/app/key","Version":3,"Decode":true}`
	w := h.serve(h.command(token, "curl", body))
	var preview struct{ Command string }
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &preview) != nil || preview.Command == "" {
		t.Fatalf("missing curl preview: %d", w.Code)
	}
	if !strings.Contains(preview.Command, h.app.cfg.Server+"/api/get") || !strings.Contains(preview.Command, `"Version":3`) || !strings.Contains(preview.Command, "python3") {
		t.Fatal("preview lost the server, version, or output selection")
	}
	for _, credential := range []string{token, "Authorization:", "Cookie:"} {
		if strings.Contains(preview.Command, credential) {
			t.Fatal("generated command included credentials")
		}
	}
	if w := h.serve(h.command(token, "copy-curl", body)); w.Code != http.StatusNoContent || copied != preview.Command {
		t.Fatal("native clipboard did not match the preview")
	}
	for _, invalid := range []string{`{}`, `null`, `[]`, `{"Name":123}`, `{"Name":"a","Version":-1}`, `{"Name":"a","Version":1.5}`, `{"Name":"a","Version":4294967296}`, `{"Name":"a","Decode":"yes"}`} {
		if w := h.serve(h.command(token, "curl", invalid)); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid request accepted: %s", invalid)
		}
	}
	h.app.cfg.CopyText = func(string) error { return errors.New("private clipboard error") }
	if w := h.serve(h.command(token, "copy-curl", body)); w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "private clipboard") {
		t.Fatal("clipboard failure was not handled safely")
	}
	h.app.cfg.CopyText = nil
	if w := h.serve(h.command(token, "copy-curl", body)); w.Code != http.StatusNotFound {
		t.Fatal("native route available without native hooks")
	}
	if h.commandCalls != 0 {
		t.Fatal("command generation must never contact Setec")
	}
}
