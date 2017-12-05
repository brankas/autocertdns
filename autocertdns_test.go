package autocertdns

import (
	"bytes"
	"context"
	"io/ioutil"
	"os"
	"testing"

	"github.com/brankas/autocertdns/godop"
)

func TestRenew(t *testing.T) {
	ctxt := context.Background()

	token, err := getToken()
	if err != nil {
		t.Fatalf("no godo token available: %v", err)
	}

	// create godo (digital ocean) client
	doClient, err := godop.New(
		godop.WithDomain("brank.as"),
		godop.FromClientToken(ctxt, token),
		godop.WithLogf(t.Logf), godop.WithErrorf(t.Logf),
	)
	if err != nil {
		t.Fatalf("could not create godo client: %v", err)
	}

	m := &Manager{
		DirectoryURL: LetsEncryptStagingURL,
		Prompt:       AcceptTOS,
		CacheDir:     "cache",
		Email:        "kenneth.shaw@brank.as",
		Domain:       "long-test-hostname-forever-long.test.brank.as",
		Provisioner:  doClient,
	}

	err = m.renew(ctxt)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

// getToken checks the environment variable GODO_TOKEN and then looks in the
// file on disk .godo-token
func getToken() (string, error) {
	if s := os.Getenv("GODO_TOKEN"); s != "" {
		return s, nil
	}
	tok, err := ioutil.ReadFile(".godo-token")
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(tok)), nil
}
