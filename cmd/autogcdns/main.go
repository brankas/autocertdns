// Command autogcdns provides cli tool to generate letsencrypt certificates
// using DNS-01 challenges for Google Cloud DNS managed zones.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kenshaw/jwt/gserviceaccount"
	"golang.org/x/crypto/acme/autocert"
	dns "google.golang.org/api/dns/v2beta1"

	"github.com/brankas/autocertdns"
	"github.com/brankas/autocertdns/gcdnsp"
)

var (
	flagCreds   = flag.String("creds", "", "path to credentials")
	flagDomain  = flag.String("d", "", "domain to generate a certificate for")
	flagZone    = flag.String("z", "", "managed zone name")
	flagCerts   = flag.String("certs", "certs", "certificates path")
	flagEmail   = flag.String("email", "", "registration email account")
	flagProject = flag.String("project", "", "project id")

	flagWait    = flag.Duration("wait", 180*time.Second, "propagation wait")
	flagDelay   = flag.Duration("delay", 20*time.Second, "provision delay")
	flagTimeout = flag.Duration("timeout", 5*time.Minute, "timeout")
)

func main() {
	flag.Parse()

	ctxt, cancel := context.WithTimeout(context.Background(), *flagTimeout)
	defer cancel()

	if err := run(ctxt); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctxt context.Context) error {
	// normalize domain and validate domain and creds have been passed
	*flagDomain = strings.TrimSuffix(*flagDomain, ".")
	if *flagDomain == "" || *flagCreds == "" {
		return errors.New("must specify domain and creds")
	}
	*flagDomain += "."

	var err error

	// load credentials
	buf, err := ioutil.ReadFile(*flagCreds)
	if err != nil {
		return err
	}

	// build service account token source
	gsa, err := gserviceaccount.FromJSON(buf, gserviceaccount.WithTransport(transportFromEnv()))
	if err != nil {
		return err
	}

	// create gsa client
	gsaClient, err := gsa.Client(
		ctxt,
		dns.CloudPlatformScope,
		dns.NdevClouddnsReadwriteScope,
	)

	// create dns service client
	dnsService, err := dns.New(gsaClient)
	if err != nil {
		return err
	}

	// copy project id if none specified
	if *flagProject == "" {
		*flagProject = gsa.ProjectID
	}

	// determine the managed zone name
	if *flagZone == "" {
		if *flagZone, err = loadZone(ctxt, gsa, dnsService); err != nil {
			return err
		}
	}

	// force an email address
	if *flagEmail == "" {
		*flagEmail = "admin@" + *flagDomain
	}

	// create provisioner
	p, err := gcdnsp.New(
		gcdnsp.Domain(*flagDomain),
		gcdnsp.ManagedZone(*flagZone),
		gcdnsp.ProjectID(*flagProject),
		gcdnsp.DNSService(dnsService),
		gcdnsp.PropagationWait(*flagWait),
		gcdnsp.ProvisionDelay(*flagDelay),
		gcdnsp.IgnorePropagationErrors,
		gcdnsp.Logf(log.Printf),
		gcdnsp.Errorf(func(string, ...interface{}) {}),
	)
	if err != nil {
		return err
	}

	// ensure directory exists
	if err = os.MkdirAll(*flagCerts, 0700); err != nil {
		return err
	}

	// create manager
	m := &autocertdns.Manager{
		Prompt:      autocert.AcceptTOS,
		Domain:      *flagDomain,
		Email:       *flagEmail,
		CacheDir:    *flagCerts,
		Provisioner: p,
		Logf:        log.Printf,
		Errorf:      func(string, ...interface{}) {},
	}

	// run
	if err = m.Run(ctxt); err != nil {
		return err
	}

	return nil
}

// loadZone determines the managed zone for the provided domain and
// credentials.
func loadZone(ctxt context.Context, gsa *gserviceaccount.GServiceAccount, dnsService *dns.Service) (string, error) {
	// list managed zones
	res, err := dnsService.ManagedZones.List(*flagProject).Do()
	if err != nil {
		return "", err
	}

	if len(res.ManagedZones) == 0 {
		return "", fmt.Errorf("no managed zones in project %q", *flagProject)
	}

	// find the managed zone with the longest dns name matching the domain flag
	zone := res.ManagedZones[0]
	for _, z := range res.ManagedZones {
		if strings.HasSuffix(*flagDomain, zone.DnsName) && len(z.DnsName) > len(zone.DnsName) {
			zone = z
		}
	}
	if !strings.HasSuffix(*flagDomain, zone.DnsName) {
		return "", fmt.Errorf("can not find the managed zone name in project %q for domain %q", *flagProject, *flagDomain)
	}

	return zone.Name, nil
}

// transportFromEnv builds a http transport from environment variables, adding
// a HTTP proxy if HTTP_PROXY or HTTPS_PROXY has been set.
func transportFromEnv() http.RoundTripper {
	for _, v := range []string{"HTTPS_PROXY", "HTTP_PROXY"} {
		if proxy := os.Getenv(v); proxy != "" {
			if u, err := url.Parse(proxy); err == nil {
				return &http.Transport{
					Proxy: http.ProxyURL(u),
				}
			}
		}
	}
	return nil
}
