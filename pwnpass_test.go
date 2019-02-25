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
	"36E618512A68721F032470BB0891ADEF3362CFA9": 23,  // p@ssword
	"36E61AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIII": 526, // unknown, first five characters are the same as above
	"D50F3D3D525303997D705F86CD80182365F964ED": 3,   // drowssap
	"E01C66B9CC16930797BF7E13BEF6B05997370B2C": 1,   // m3atba11
}

func fakePwnedServer(t *testing.T, shouldTimeout bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if shouldTimeout {
			rw.Header().Add(http.CanonicalHeaderKey("retry-after"), "1500")
			rw.WriteHeader(http.StatusTooManyRequests)
			return
		}

		// Test request parameters
		path := req.URL.String()
		if len(path) != pathLen {
			t.Errorf("unexpected path length: got %d, want %d (path: %s)", len(path), pathLen, path)
		}

		// Send response to be tested.
		for pass, res := range passwords {
			pathUpper := strings.ToUpper(path[1:6])
			if pathUpper == pass[:5] {
				resp := fmt.Sprintf("%s:%d\n", pass[5:], res)
				rw.Write([]byte(resp))
			}
		}
	}))
}

func TestMatch(t *testing.T) {
	tests := []struct {
		desc          string
		password      string
		want          int
		wantErr       bool
		shouldTimeout bool
	}{
		{
			desc:     "basic_working_hash",
			password: "p@ssword",
			want:     23,
		},
		{
			desc:     "password_not_in_db",
			password: "v3rysecureP@ssw0rd",
			want:     0,
		},
		{
			desc:          "timed_out",
			password:      "lol",
			want:          -1,
			shouldTimeout: true,
			wantErr:       true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			server := fakePwnedServer(t, tc.shouldTimeout)
			defer server.Close()

			client := Client{
				client: server.Client(),
				url:    server.URL,
			}

			hash := sha1.New()
			io.WriteString(hash, tc.password)

			got, err := client.Match(hash)
			if gotErr := (err != nil); gotErr != tc.wantErr {
				t.Errorf("client.Match() returned unexpected error: %v", err)
				return
			}

			if got != tc.want {
				t.Errorf("client.Match() got %v, want %v", got, tc.want)
			}
		})
	}
}
