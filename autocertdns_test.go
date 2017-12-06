package autocertdns

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
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

	host, err := randHost()
	if err != nil {
		t.Fatalf("could not generate random host, got: %v", err)
	}
	host += ".test.brank.as"

	m := &Manager{
		DirectoryURL: LetsEncryptStagingURL,
		Prompt:       AcceptTOS,
		CacheDir:     "cache",
		Email:        "kenneth.shaw@brank.as",
		Domain:       host,
		Provisioner:  doClient,
		Logf:         t.Logf,
		//Errorf:       t.Errorf,
	}

	err = m.renew(ctxt)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	for _, f := range []string{
		"acme_account.key",
		host + ".key",
		host + ".crt",
	} {
		n := filepath.Join("cache", f)
		_, err := os.Stat(n)
		if err != nil {
			t.Errorf("expected %s to exist, got: %v", n, err)
		}
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

func randHost() (string, error) {
	buf := make([]byte, 1024)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}
	h := md5.New()
	_, err = h.Write(buf)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
