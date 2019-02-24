package pwnpass

import (
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Expected path length for requests. Should be a forward slash '/' followed
// by 5 hex characters.
const pathLen = 6

// A map of password SHA1 hashes to the number of (fake) results found.
var passwords = map[string]int{
	"36E618512A68721F032470BB0891ADEF3362CFA9": 23, // p@ssword
}

func TestMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		path := req.URL.String()
		if len(path) != pathLen {
			t.Errorf("unexpected path length: got %d, want %d (path: %s)", len(path), pathLen, path)
		}

		// Send response to be tested
		for pass, res := range passwords {
			pathUpper := strings.ToUpper(path[1:6])
			if pathUpper == pass[:5] {
				resp := fmt.Sprintf("%s:%d", pass[5:], res)
				rw.Write([]byte(resp))
			}
		}
	}))
	defer server.Close()

	client := Client{
		client: server.Client(),
		url:    server.URL,
	}

	tests := []struct {
		desc     string
		password string
		want     int
		wantErr  bool
	}{
		{
			desc:     "basic_working_hash",
			password: "p@ssword",
			want:     23,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			hash := sha1.New()
			io.WriteString(hash, tc.password)

			got, err := client.Match(hash)
			if gotErr := (err != nil); gotErr != tc.wantErr {
				t.Errorf("client.Match() returned unexpected error: %v", err)
			}

			if got != tc.want {
				t.Errorf("client.Match() got %v, want %v", got, tc.want)
			}
		})
	}
}
