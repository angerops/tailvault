package portal

import (
	"encoding/json"
	"strings"
)

type curlRequest struct {
	Name    string
	Version uint32 `json:",omitempty"`
	Decode  bool   `json:"-"`
}

// curlCommand uses only the configured server and secret metadata. It does not
// fetch a value or include the native view handle or any credentials.
func curlCommand(server string, input curlRequest) string {
	body, _ := json.Marshal(input)
	command := strings.Join([]string{
		"curl --disable --fail --silent --show-error",
		"  --noproxy '*'",
		"  --request POST",
		"  --header 'Sec-X-Tailscale-No-Browsers: setec'",
		"  --header 'Content-Type: application/json'",
		"  --data-raw " + shellQuote(string(body)),
		"  " + shellQuote(server+"/api/get"),
	}, " \\\n")
	if input.Decode {
		command += " |\n  python3 -c 'import base64,json,sys; sys.stdout.buffer.write(base64.b64decode(json.load(sys.stdin)[\"Value\"], validate=True))'"
	}
	return command
}

// POSIX single quotes preserve dollars, backticks, backslashes, and newlines.
// A literal apostrophe temporarily closes the quoted string and is double quoted.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
