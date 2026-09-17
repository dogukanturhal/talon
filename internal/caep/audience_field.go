// SPDX-License-Identifier: AGPL-3.0-or-later

package caep

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// audienceField decodes the `aud` claim per RFC 7519 §4.1.3 — MAY be
// a single string OR an array of strings. CAEP SETs typically use a
// single audience (the receiver URL), but the JWT spec permits both
// and consumers must tolerate both. We canonicalize to []string
// internally; serialization preserves a 1-element array.
type audienceField []string

func (a audienceField) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

func (a *audienceField) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*a = audienceField{s}
		return nil
	}
	if data[0] == '[' {
		var ss []string
		if err := json.Unmarshal(data, &ss); err != nil {
			return err
		}
		*a = audienceField(ss)
		return nil
	}
	return fmt.Errorf("aud: expected string or array, got %s", data[:1])
}

// contains reports whether expected appears in the audience claim.
func (a audienceField) contains(expected string) bool {
	for _, v := range a {
		if v == expected {
			return true
		}
	}
	return false
}
