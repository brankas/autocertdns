// Package godop provides a godo (DigitalOcean API) compatible autocertdns.Provisioner.
package godop

import (
	"context"
	"errors"
	"strings"

	"github.com/digitalocean/godo"
)

// Client wraps a DigitalOcean godo.Client.
type Client struct {
	*godo.Client
	domain string
}

// New wraps a godo.Client with a Client that can also handle DNS provisioning
// requests for use with the autocertdns.Manager.
func New(c *godo.Client, domain string) *Client {
	return &Client{Client: c, domain: domain}
}

// Provision creates a DNS record of typ, for the specified domain name and
// with the value in token.
func (c *Client) Provision(ctxt context.Context, typ, name, token string) error {
	if typ != "TXT" {
		return errors.New("only TXT records are supported")
	}

	// check name
	if !strings.HasSuffix(name, "."+c.domain) {
		return errors.New("invalid domain")
	}
	name = name[:len(name)-len(c.domain)-1]
	if name == "" {
		return errors.New("invalid name")
	}

	// create dns record
	_, _, err := c.Domains.CreateRecord(ctxt, c.domain, &godo.DomainRecordEditRequest{
		Type: "TXT",
		Name: name,
		Data: token,
	})
	if err != nil {
		return err
	}

	return nil
}

// Unprovision deletes the DNS record of typ, for the specified domain name,
// and for the record with the specified token as the value.
func (c *Client) Unprovision(ctxt context.Context, typ, name, token string) error {
	var err error

	if typ != "TXT" {
		return errors.New("only TXT records are supported")
	}

	// check name
	if !strings.HasSuffix(name, "."+c.domain) {
		return errors.New("invalid domain")
	}
	name = name[:len(name)-len(c.domain)-1]
	if name == "" {
		return errors.New("invalid name")
	}

	// get current records
	records, _, err := c.Domains.Records(ctxt, c.domain, nil)
	if err != nil {
		return err
	}

	// find record and delete if TXT record and token matches
	for _, record := range records {
		if record.Name != name || record.Type != "TXT" || record.Data != token {
			continue
		}

		_, err = c.Domains.DeleteRecord(ctxt, c.domain, record.ID)
		if err != nil {
			return err
		}

		return nil
	}

	return errors.New("record not deleted")
}