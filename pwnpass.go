package pwnpass

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"hash"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const rangeEP = "https://api.pwnedpasswords.com/range/"

// TooManyRequests is returned by Match when too many subsequent API calls have
// been made. RetryIn will contain the number of seconds to wait before
// retrying.
type TooManyRequests struct {
	RetryIn int
}

func (e *TooManyRequests) Error() string {
	return fmt.Sprintf("too many requests, retry in %d seconds", e.RetryIn)
}

// Client that holds the URL and HTTP client.
type Client struct {
	client *http.Client
	url    string
}

// New returns a new Client with the default URL and HTTP client.
func New() *Client {
	c := Client{
		client: http.DefaultClient,
		url:    rangeEP,
	}
	return &c
}

// Match takes a hash.Hash and returns the number of passwords
// found that match that hash. In the event of an error, the
// function will return -1 and the error.
// Normally API calls can only be made every 1500ms per IP.
// If this limit is exceeded error will be set to TooManyRequests, which
// contains the item RetryIn. RetryIn is the number of seconds to wait before
// trying to make another Match() call.
// Defined at https://haveibeenpwned.com/API/v2#PwnedPasswords.
func (c *Client) Match(h hash.Hash) (int, error) {
	hs := hex.EncodeToString(h.Sum(nil))
	g := fmt.Sprintf("%s/%s", c.url, hs[:5])

	resp, err := c.client.Get(g)
	if err != nil {
		return -1, fmt.Errorf("could not GET %s: %v", g, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusTooManyRequests {
			// Extract retry time.
			r := resp.Header.Get("retry-after")
			ri, err := strconv.Atoi(r)
			if err != nil {
				return -1, fmt.Errorf("could not convert string to int: %v", err)
			}
			return -1, &TooManyRequests{RetryIn: ri}
		}
		return -1, fmt.Errorf("expected status OK (200), got: %s (%d)", resp.Status, resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	hsUpper := strings.ToUpper(hs[5:])
	for scanner.Scan() {
		s := strings.Split(scanner.Text(), ":")
		if s[0] == hsUpper {
			si, err := strconv.Atoi(s[1])
			if err != nil {
				return -1, fmt.Errorf("could not convert string to int: %v", err)
			}
			return si, nil
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "could not read: %v", err)
	}
	return 0, nil
}
