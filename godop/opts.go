package godop

import (
	"bytes"
	"context"
	"io/ioutil"

	"github.com/digitalocean/godo"
	"golang.org/x/oauth2"
)

// Option is the client option type.
type Option func(c *Client) error

// WithDomain is a client option to configure the domain.
func WithDomain(domain string) Option {
	return func(c *Client) error {
		c.domain = domain
		return nil
	}
}

// WithClient is a client option to pass an already created godo client.
func WithClient(client *godo.Client) Option {
	return func(c *Client) error {
		c.Client = client
		return nil
	}
}

// FromClientToken is a client option to pass only the godo client token, and a
// new godo client will be created.
func FromClientToken(ctxt context.Context, token string) Option {
	return func(c *Client) error {
		return WithClient(godo.NewClient(oauth2.NewClient(
			ctxt,
			oauth2.StaticTokenSource(
				&oauth2.Token{
					AccessToken: token,
				},
			),
		)))(c)
	}
}

// FromClientTokenFile is a client option to create a new godo client using a
// token stored in file on disk.
func FromClientTokenFile(ctxt context.Context, filename string) Option {
	return func(c *Client) error {
		tok, err := ioutil.ReadFile(filename)
		if err != nil {
			return err
		}

		return FromClientToken(ctxt, string(bytes.TrimSpace(tok)))(c)
	}
}

// WithLogf is a client option to specify the logging function used.
func WithLogf(f func(string, ...interface{})) Option {
	return func(c *Client) error {
		c.logf = f
		return nil
	}
}

// WithErrorf is a client option to specify the error logging function used.
func WithErrorf(f func(string, ...interface{})) Option {
	return func(c *Client) error {
		c.errf = f
		return nil
	}
}
