// Package autocertdns provides autocertificate renewal from LetsEncrypt using
// DNS-01 challenges.
package autocertdns

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/knq/pemutil"
	"golang.org/x/crypto/acme"
)

const (
	// acmeKeyFile is the name of the ACME key file used with the directory
	// cache.
	acmeKeyFile = "acme_account.key"

	// acmeChallengDomainPrefix is the ACME challenge domain prefix.
	acmeChallengDomainPrefix = "_acme-challenge."

	// keySuffix is the filename suffix for cached key files.
	keySuffix = ".key"

	// certSuffix is the filename suffix for cached certificate files.
	certSuffix = ".crt"

	// LetsEncryptURL is the default ACME server URL.
	LetsEncryptURL = acme.LetsEncryptURL

	// LetsEncryptStagingURL is the ACME staging server URL, used for testing
	// purposes.
	LetsEncryptStagingURL = "https://acme-staging.api.letsencrypt.org/directory"
)

// Provisioner is the shared interface for providers that can provision DNS
// records.
type Provisioner interface {
	// Provision provisions a DNS entry of typ (always TXT), for the FQDN name
	// and with the provided token.
	Provision(ctxt context.Context, typ, name, token string) error

	// Unprovision unprovisions a DNS entry of typ (always TXT), for the FQDN
	// name and with the provided token.
	Unprovision(ctxt context.Context, typ, name, token string) error
}

// Manager holds information related to managing a DNS-01 based ACME autocert
// provider.
type Manager struct {
	// DirectoryURL is the directory URL to use.
	DirectoryURL string

	// Prompt is the func used to accept the TOS.
	Prompt func(string) bool

	// CacheDir is the directory to store certificates in.
	CacheDir string

	// Email is the ACME email account.
	Email string

	// Domain is the domain to generate certificates for.
	Domain string

	// RenewBefore is the window before the expiration of a certificate,
	// after which the current certificate will attempt to be renewed.
	//
	// If zero, certificates will be renewed 5 days before expiration.
	RenewBefore time.Duration

	// Provisioner is the DNS provisioner used to provision and unprovision the
	// DNS-01 challenges given by the ACME server.
	Provisioner Provisioner

	// Logf is a logging func.
	Logf func(string, ...interface{})

	// Errorf is an error logging func.
	Errorf func(string, ...interface{})

	// cert is the current certificate.
	cert *tls.Certificate

	// nextExpiry is the next expiration date.
	nextExpiry time.Time

	rw sync.RWMutex
}

// log logs s, v via Manager.Logf.
func (m *Manager) log(s string, v ...interface{}) {
	if m.Logf != nil {
		m.Logf(s, v...)
	}
}

// errf creates an error using s and v from fmt.Errorf, reporting the error to
// the Errorf (if defined, or Logf otherwise) func, and returning the created
// error. Useful for wrapping internal errors and ensuring they are output via
// Manager.log.
func (m *Manager) errf(s string, v ...interface{}) error {
	err := fmt.Errorf(s, v...)
	if m.Errorf == nil {
		m.log("ERROR: %v", err)
	} else {
		m.Errorf(s, v)
	}
	return err
}

// loadOrRenew will attempt to load a certificate from the directory in
// Manager.DirCache, if that fails then an attempt will be made to create/renew
// a certificate based on the Manager configuration.
func (m *Manager) loadOrRenew(ctxt context.Context) error {
	return nil
}

// renew renews the certificate using the provided context.
func (m *Manager) renew(ctxt context.Context) error {
	m.rw.Lock()
	defer m.rw.Unlock()

	var err error

	if m.Email == "" {
		return m.errf("must provide Email")
	}
	if m.Prompt == nil {
		return m.errf("must provide Prompt")
	}
	if m.Provisioner == nil {
		return m.errf("must provide Provisioner")
	}

	// load acme key
	key, err := m.cachedKey(acmeKeyFile)
	if err != nil {
		return m.errf("could not load %s: %v", acmeKeyFile, err)
	}

	// create acme client
	directoryURL := m.DirectoryURL
	if directoryURL == "" {
		directoryURL = LetsEncryptURL
	}
	client := &acme.Client{
		Key:          key,
		DirectoryURL: directoryURL,
	}

	// register domain
	_, err = client.Register(ctxt, &acme.Account{
		Contact: []string{"mailto:" + m.Email},
	}, m.Prompt)
	if ae, ok := err.(*acme.Error); err == nil || ok && ae.StatusCode == http.StatusConflict {
		// already registered account
	} else if err != nil {
		return m.errf("could not register with ACME server: %v", err)
	}

	// create authorize challenges
	authz, err := client.Authorize(ctxt, m.Domain)
	if err != nil {
		return m.errf("could not authorize with ACME server: %v", err)
	}

	// grab dns challenge
	var challenge *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "dns-01" {
			challenge = c
			break
		}
	}
	if challenge == nil {
		return m.errf("no dns-01 challenge found in challenges provided by the ACME server")
	}

	// exchange dns challenge
	tok, err := client.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		return m.errf("could not generate token for ACME challenge: %v", err)
	}

	// provision TXT under _acme-challenge.<domain>
	err = m.Provisioner.Provision(ctxt, "TXT", acmeChallengDomainPrefix+m.Domain, tok)
	if err != nil {
		return m.errf("could not provision dns-01 TXT challenge: %v", err)
	}
	defer m.Provisioner.Unprovision(ctxt, "TXT", acmeChallengDomainPrefix+m.Domain, tok)

	// accept challenge
	_, err = client.Accept(ctxt, challenge)
	if err != nil {
		return m.errf("could not accept ACME challenge: %v", err)
	}

	// wait for authorization
	authz, err = client.WaitAuthorization(ctxt, authz.URI)
	if err != nil {
		return m.errf("unable to wait for authorization from ACME server: %v", err)
	} else if authz.Status != acme.StatusValid {
		return m.errf("dns-01 challenge is invalid (has status %v)", authz.Status)
	}

	// grab domain key
	certKey, err := m.cachedKey(m.Domain + keySuffix)
	if err != nil {
		return m.errf("could not load domain key: %v", err)
	}

	// create certificate signing request
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: m.Domain},
	}, certKey)
	if err != nil {
		return m.errf("could not create certificate signing request: %v", err)
	}

	// create certificate
	der, urlstr, err := client.CreateCert(ctxt, csr, 0, true)
	if err != nil {
		return m.errf("could not create certificate: %v", err)
	}

	m.log("created certificate: %s", urlstr)

	der = der

	return nil
}

// cachedKey retrieves a private key from disk, generating a new elliptic.P256
// key if the file is not on disk.
func (m *Manager) cachedKey(filename string) (*ecdsa.PrivateKey, error) {
	keyfile := filepath.Join(m.CacheDir, filename)

	// try to load cached credentials
	store, err := pemutil.LoadFile(keyfile)
	if err != nil && os.IsNotExist(err) {
		store, err = pemutil.GenerateECKeySet(elliptic.P256())
		if err != nil {
			return nil, fmt.Errorf("could not generate ec key set: %v", err)
		}
		err = os.MkdirAll(m.CacheDir, 0700)
		if err != nil {
			return nil, fmt.Errorf("could not create cache directory: %v", err)
		}
		err = store.WriteFile(keyfile)
		if err != nil {
			return nil, fmt.Errorf("could not save PEM: %v", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("unexpected error: %v", err)
	}

	// grab key
	key, ok := store.ECPrivateKey()
	if !ok {
		return nil, fmt.Errorf("%s does not contain ec private key", keyfile)
	}

	return key, nil
}

// cachedCert retrieves the certificate on disk for domain, and extracting the
// expiry date.
func (m *Manager) cachedCert(domain string) (crypto.Signer, time.Time, error) {
	certPath := filepath.Join(m.CacheDir, domain+certSuffix)
	store, err := pemutil.LoadFile(certPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, time.Time{}, err
	}

	cert, ok := store.Certificate()
	if !ok {
		return nil, time.Time{}, fmt.Errorf("%s does not contain a certificate", certPath)
	}

	// extract signer, time
	cert = cert

	return nil, time.Time{}, nil
}

// afterRenew returns a channel that will be closed after the passing the
// Manager's next expiration date.
func (m *Manager) afterRenew() <-chan time.Time {
	m.rw.RLock()
	exp := m.nextExpiry
	m.rw.RUnlock()

	return time.After(exp.Sub(time.Now()))
}

// Run starts a goroutine to automatically renew a certificate until the passed
// context has been closed. Will return an error if initially a certificate
// cannot be issued/renewed and if any cached certificate is expired.
func (m *Manager) Run(ctxt context.Context) error {
	// manually renew
	err := m.loadOrRenew(ctxt)
	if err != nil {
		return err
	}

	go func() {
		for {
			select {
			case <-m.afterRenew():
				err = m.loadOrRenew(ctxt)
				if err != nil {
					_ = m.errf("cannot renew: %v", err)
					return
				}

			case <-ctxt.Done():
				m.log("context done: %v", ctxt.Err())
				return
			}
		}
	}()

	return nil
}

// GetCertificate returns the current certificate.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.rw.RLock()
	defer m.rw.RUnlock()

	return m.cert, nil
}

// AcceptTOS is a util func that always returns true to indicate acceptance of
// the underlying ACME server's Terms of Service during account registration.
func AcceptTOS(string) bool {
	return true
}
