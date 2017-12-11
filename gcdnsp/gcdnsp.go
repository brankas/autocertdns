// Package gcdnsp provides a Google Cloud DNS client that satisfies
// autocertdns.Provisioner.
package gcdnsp

import (
	"context"
	"errors"
	"strings"
	"time"

	dnsr "github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
	dns "google.golang.org/api/dns/v2beta1"
)

const (
	// allowedRecordType is the allowed record provisioning type.
	allowedRecordType = "TXT"

	// DefaultPropagationWait is the default propagation waiting time.
	DefaultPropagationWait = 60 * time.Second

	// DefaultCheckDelay is the default check delay
	DefaultCheckDelay = 100 * time.Millisecond

	// DefaultProvisionDelay is the default after provision wait delay.
	DefaultProvisionDelay = 10 * time.Second
)

// Client wraps a Google Cloud DNS service.
type Client struct {
	projectID       string
	managedZone     string
	domain          string
	nameservers     []string
	dnsService      *dns.Service
	propagationWait time.Duration
	checkDelay      time.Duration
	provisionDelay  time.Duration
	logf            func(string, ...interface{})
	errf            func(string, ...interface{})
}

// New wraps a Google Cloud DNS Service in order to handle DNS provisioning
// requests (for use with the autocertdns.Manager).
func New(opts ...Option) (*Client, error) {
	var err error

	c := &Client{
		logf: func(string, ...interface{}) {},
		nameservers: []string{
			"ns-cloud-b1.googledomains.com:53",
			"ns-cloud-b2.googledomains.com:53",
			"ns-cloud-b3.googledomains.com:53",
			"ns-cloud-b4.googledomains.com:53",
		},
		propagationWait: DefaultPropagationWait,
		checkDelay:      DefaultCheckDelay,
		provisionDelay:  DefaultProvisionDelay,
	}

	// apply opts
	for _, o := range opts {
		err = o(c)
		if err != nil {
			return nil, err
		}
	}

	// ensure errf is set
	if c.errf == nil {
		c.errf = func(s string, v ...interface{}) {
			c.logf("ERROR: "+s, v...)
		}
	}

	if c.managedZone == "" || c.domain == "" || c.dnsService == nil {
		return nil, errors.New("gcdnsp missing managed zone, domain, or dns service")
	}

	// force end .
	c.domain = strings.TrimSuffix(c.domain, ".")

	return c, nil
}

// Provision creates a DNS record of typ, for the specified domain name and
// with the value in token.
func (c *Client) Provision(ctxt context.Context, typ, name, token string) error {
	if typ != allowedRecordType {
		return errors.New("only TXT records are supported")
	}

	// check name
	if !strings.HasSuffix(name, "."+c.domain) {
		return errors.New("invalid domain")
	}
	if n := strings.TrimSuffix(name, "."+c.domain); n == "" {
		return errors.New("invalid name")
	}
	name += "."

	// create dns record
	c.logf("provisioning (type: %s, name: %s, token: %s)", typ, name, token)
	_, err := dns.NewChangesService(c.dnsService).Create(
		c.projectID, c.managedZone,
		&dns.Change{
			Additions: []*dns.ResourceRecordSet{
				&dns.ResourceRecordSet{
					Type:    typ,
					Name:    name,
					Rrdatas: []string{token},
					Ttl:     1,
				},
			},
		},
	).Do()
	if err != nil {
		c.errf("unable to provision (type: %s, name: %s, token: %s): %v", typ, name, token, err)
		return err
	} /*else {
		c.logf("successfully provisioned (type: %s, name: %s, token: %s)", typ, name, token)
	}*/

	var cancel func()
	ctxt, cancel = context.WithTimeout(ctxt, c.propagationWait)
	defer cancel()

	eg, ctxt := errgroup.WithContext(ctxt)
	for _, nn := range c.nameservers {
		ns := nn
		eg.Go(func() error {
			// create dnsr client and question
			cl := new(dnsr.Client)
			m := new(dnsr.Msg)
			m.SetQuestion(name, dnsr.TypeTXT)
			for {
				select {
				case <-ctxt.Done():
					return ctxt.Err()
				default:
					// query nameserver
					res, _, err := cl.Exchange(m, ns)
					if err == nil && len(res.Answer) > 0 {
						for _, a := range res.Answer {
							if txtRecord, ok := a.(*dnsr.TXT); ok && contains(txtRecord.Txt, token) {
								return nil
							}
						}
					}
					time.Sleep(c.checkDelay)
				}
			}

			return nil
		})
	}

	err = eg.Wait()
	if err != nil {
		return err
	}

	time.Sleep(c.provisionDelay)

	return nil
}

// Unprovision deletes the DNS record of typ, for the specified domain name,
// and for the record with the specified token as the value.
func (c *Client) Unprovision(ctxt context.Context, typ, name, token string) error {
	var err error

	if typ != allowedRecordType {
		return errors.New("only TXT records are supported")
	}

	// check name
	if !strings.HasSuffix(name, "."+c.domain) {
		return errors.New("invalid domain")
	}
	if n := strings.TrimSuffix(name, "."+c.domain); n == "" {
		return errors.New("invalid name")
	}
	name += "."

	// get current records
	//c.logf("retrieving records (type: %s, name: %s, token: %s)", typ, name, token)
	req := dns.NewResourceRecordSetsService(c.dnsService).List(
		c.projectID, c.managedZone,
	)

	// find rrsets to delete if TXT record and token matches
	var deletions []*dns.ResourceRecordSet
	if err = req.Pages(ctxt, func(page *dns.ResourceRecordSetsListResponse) error {
		for _, rrSet := range page.Rrsets {
			//log.Printf(">>>> name: %s, type: %s, rrdatas: %v", rrSet.Name, rrSet.Type, rrSet.Rrdatas)
			if rrSet.Name != name || rrSet.Type != allowedRecordType || !contains(rrSet.Rrdatas, token) {
				continue
			}
			deletions = append(deletions, rrSet)
		}
		return nil

	}); err != nil {
		c.errf("could not retrieve records (type: %s, name: %s, token: %s): %v", typ, name, token, err)
		return err
	}

	if len(deletions) < 1 {
		c.errf("could not find record (type: %s, name: %s, token: %s)", typ, name, token)
		return nil
	}

	c.logf("unprovisioning (type: %s, name: %s, token: %s)", typ, name, token)
	_, err = dns.NewChangesService(c.dnsService).Create(
		c.projectID, c.managedZone,
		&dns.Change{
			Deletions: deletions,
		},
	).Do()
	if err != nil {
		c.errf("unable to unprovision (type: %s, name: %s, token: %s): %v", typ, name, token, err)
		return err
	} /* else {
		c.logf("successfully unprovisioned (type: %s, name: %s, token: %s)", typ, name, token)
	}*/
	return nil
}

// contains returns true if haystack contains needle.
func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if needle == strings.TrimFunc(s, func(r rune) bool { return r == '"' }) {
			return true
		}
	}
	return false
}
