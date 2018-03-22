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
	"time"

	"github.com/brankas/autocertdns/gcdnsp"
	"github.com/brankas/autocertdns/godop"
)

const (
	gcdnspManagedZone = "dns-ken"
	gcdnspDomain      = "ken.dev.brank.as"
	godopDomain       = "godo." + gcdnspDomain
)

func TestRenewGoogleCloudDNS(t *testing.T) {
	t.Parallel()

	ctxt := context.Background()

	creds, err := getEnvOrFile("GOOGLE_CREDS", ".gsa.json")
	if err != nil {
		t.Fatalf("no google service account credentials available: %v", err)
	}

	// create google cloud dns provisioner
	client, err := gcdnsp.New(
		gcdnsp.ManagedZone(gcdnspManagedZone),
		gcdnsp.Domain(gcdnspDomain),
		gcdnsp.GoogleServiceAccountCredentialsJSON([]byte(creds)),
		gcdnsp.PropagationWait(180*time.Second),
		gcdnsp.ProvisionDelay(30*time.Second),
		gcdnsp.Logf(t.Logf),
	)
	if err != nil {
		t.Fatalf("could not create gcdnsp client: %v", err)
	}

	host, err := randHost()
	if err != nil {
		t.Fatalf("could not generate random host, got: %v", err)
	}
	host += "." + gcdnspDomain

	m := &Manager{
		DirectoryURL: LetsEncryptStagingURL,
		Prompt:       AcceptTOS,
		CacheDir:     "cache",
		Email:        "kenneth.shaw@brank.as",
		Domain:       host,
		Provisioner:  client,
		Logf:         t.Logf,
		//Errorf:       t.Errorf,
	}

	err = m.renew(ctxt)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
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

func TestRenewGodop(t *testing.T) {
	t.Parallel()

	ctxt := context.Background()

	token, err := getEnvOrFile("GODO_TOKEN", ".godo-token")
	if err != nil {
		t.Fatalf("no godo token available: %v", err)
	}

	// create godo (digital ocean) provisioner
	client, err := godop.New(
		godop.Domain("brank.as"),
		godop.GodoClientToken(ctxt, token),
		godop.Logf(t.Logf),
	)
	if err != nil {
		t.Fatalf("could not create godo client: %v", err)
	}

	host, err := randHost()
	if err != nil {
		t.Fatalf("could not generate random host, got: %v", err)
	}
	host += "." + godopDomain

	m := &Manager{
		DirectoryURL: LetsEncryptStagingURL,
		Prompt:       AcceptTOS,
		CacheDir:     "cache",
		Email:        "kenneth.shaw@brank.as",
		Domain:       host,
		Provisioner:  client,
		Logf:         t.Logf,
		//Errorf:       t.Errorf,
	}

	err = m.renew(ctxt)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
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

// getEnvOrFile checks the specifiied environment variable name, returning its
// value or loading the data from the filename.
func getEnvOrFile(name, filename string) (string, error) {
	if s := os.Getenv(name); s != "" {
		return s, nil
	}
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(buf)), nil
}

// randHost generates a random string.
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
