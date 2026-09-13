package portal

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMalformedMetadataNeverReachesTheFrontend(t *testing.T) {
	for _, body := range []string{
		`{"Name":"a","Versions":["<span>private-marker</span>"],"ActiveVersion":1}`,
		`{"Name":"a","Versions":[0],"ActiveVersion":0}`,
		`{"Name":"a","Versions":[4294967296],"ActiveVersion":1}`,
		`{"Name":"a","Versions":[-1],"ActiveVersion":1}`,
		`{"Name":"a","Versions":[1.5],"ActiveVersion":1}`,
		`{"Name":"a","Versions":[true],"ActiveVersion":1}`,
		`{"Name":"a","Versions":[null],"ActiveVersion":1}`,
		`{"Name":"a","Versions":[1,1],"ActiveVersion":1}`,
		`{"Name":"a","Versions":[1],"ActiveVersion":2}`,
		`{"Name":"a","Versions":null,"ActiveVersion":1}`,
		`{"Name":1,"Versions":[1],"ActiveVersion":1}`,
		`null`, `{}`, `[]`,
	} {
		for _, op := range []string{"list", "info"} {
			t.Run(op+body, func(t *testing.T) {
				h := newHarness(t)
				token := h.open(t)
				responseBody := body
				if op == "list" {
					responseBody = "[" + body + "]"
				}
				h.commandBody = []byte(responseBody)
				w := h.serve(h.command(token, op, `{}`))
				if w.Code != 502 || w.Body.String() != "Setec returned invalid secret metadata.\n" {
					t.Fatalf("malformed metadata was not rejected safely: status %d", w.Code)
				}
			})
		}
	}
}

func TestMetadataPreservesProviderValuesAndCanonicalizesFields(t *testing.T) {
	for _, op := range []string{"list", "info"} {
		body := `{"Name":"a/<b>","Versions":[1,4294967295],"ActiveVersion":1,"unused":"private-marker"}`
		if op == "list" {
			body = "[" + body + "]"
		}
		result, err := sanitizeMetadata(op, []byte(body))
		if err != nil || strings.Contains(string(result), "private-marker") || !json.Valid(result) {
			t.Fatal("valid metadata was not safely projected")
		}
	}
	for _, body := range []string{`null`, `[]`} {
		if _, err := sanitizeMetadata("list", []byte(body)); err != nil {
			t.Fatal("empty provider list rejected")
		}
	}
	result, err := sanitizeMetadata("info", []byte(`{"Name":"a","Versions":[1],"versions":[2],"ActiveVersion":2}`))
	if err != nil || string(result) != `{"Name":"a","Versions":[2],"ActiveVersion":2}` {
		t.Fatal("ambiguous fields were not canonicalized")
	}
}
