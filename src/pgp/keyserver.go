package pgp

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// keyserverTimeout bounds each individual keyserver HTTP request so a slow
// or unresponsive keyserver cannot hang key publication indefinitely.
const keyserverTimeout = 15 * time.Second

// PublishResult is the outcome of publishing a public key to one keyserver.
type PublishResult struct {
	Host string
	Err  error
}

// publishRetries and publishBackoff bound the exponential-backoff retry
// loop used for each keyserver submission (AI.md PART 11 "Publish to
// keyservers": "Failures are logged + retried with exponential backoff").
// Declared as vars (not consts) so tests can shrink them to keep the retry
// loop fast; production code never reassigns them.
var (
	publishRetries = 3
	publishBackoff = 2 * time.Second
)

// vksScheme is the URL scheme used for keyserver submission. Declared as a
// var so tests can point it at a local httptest.Server over plain HTTP;
// production code never reassigns it.
var vksScheme = "https"

// vksUploadRequest is the request body for the VKS-style HTTP submission API
// used by keys.openpgp.org, keyserver.ubuntu.com, and compatible keyservers.
type vksUploadRequest struct {
	Keytext string `json:"keytext"`
}

// Publish POSTs the public key to every host in keyservers (VKS-style
// submission endpoint), recording success per host into pgp_keypairs via
// RecordKeyserverPublish. Returns one PublishResult per keyserver.
func Publish(db *sql.DB, fingerprint, publicArmor string, keyservers []string) []PublishResult {
	results := make([]PublishResult, 0, len(keyservers))
	for _, host := range keyservers {
		err := publishOne(host, publicArmor)
		if err == nil {
			if dbErr := RecordKeyserverPublish(db, fingerprint, host, time.Now()); dbErr != nil {
				err = dbErr
			}
		}
		results = append(results, PublishResult{Host: host, Err: err})
	}
	return results
}

// publishOne submits the key to a single keyserver, retrying with
// exponential backoff on transient failure.
func publishOne(host, publicArmor string) error {
	body, err := json.Marshal(vksUploadRequest{Keytext: publicArmor})
	if err != nil {
		return fmt.Errorf("pgp: encode upload request: %w", err)
	}

	url := fmt.Sprintf("%s://%s/vks/v1/upload", vksScheme, host)

	var lastErr error
	for attempt := 0; attempt < publishRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(publishBackoff * time.Duration(1<<uint(attempt-1)))
		}

		ctx, cancel := context.WithTimeout(context.Background(), keyserverTimeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			cancel()
			lastErr = fmt.Errorf("pgp: build request for %s: %w", host, err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		cancel()
		if err != nil {
			lastErr = fmt.Errorf("pgp: publish to %s: %w", host, err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("pgp: publish to %s: unexpected status %d", host, resp.StatusCode)
	}

	return lastErr
}
