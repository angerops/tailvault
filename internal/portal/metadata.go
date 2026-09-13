package portal

import (
	"encoding/json"
	"errors"
)

// secretMetadata is the list/info wire projection of Setec's api.SecretInfo,
// not a separate secret model. Re-encoding prevents ambiguous duplicate or
// differently cased JSON fields from being interpreted differently by the UI.
type secretMetadata struct {
	Name          string
	Versions      []uint32
	ActiveVersion uint32
}

func (m secretMetadata) valid() bool {
	if m.Name == "" || m.ActiveVersion == 0 || len(m.Versions) == 0 {
		return false
	}
	seen := make(map[uint32]bool, len(m.Versions))
	for _, version := range m.Versions {
		if version == 0 || seen[version] {
			return false
		}
		seen[version] = true
	}
	return seen[m.ActiveVersion]
}

func sanitizeMetadata(op string, data []byte) ([]byte, error) {
	invalid := errors.New("invalid Setec metadata")
	if op == "list" {
		var items []secretMetadata
		if json.Unmarshal(data, &items) != nil {
			return nil, invalid
		}
		for _, item := range items {
			if !item.valid() {
				return nil, invalid
			}
		}
		return json.Marshal(items)
	}
	var item secretMetadata
	if json.Unmarshal(data, &item) != nil || !item.valid() {
		return nil, invalid
	}
	return json.Marshal(item)
}
