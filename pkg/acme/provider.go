package acme

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/loopholelabs/certifier/pkg/options"
	"github.com/loopholelabs/certifier/pkg/storage"
	"github.com/loopholelabs/logging"
)

var _ challenge.Provider = (*provider)(nil)

// provider satisfies the challenge.Provider interface for renewing
// ACME Certificates using the DNS-01 Challenge
type provider struct {
	// options contains the options used to configure this instance of provider
	options *options.Options

	// cid is the CID for this provider
	cid string

	// domain is the domain for this instance of provider
	domain string
}

func newProvider(cid string, domain string, options *options.Options) *provider {
	return &provider{
		cid:     cid,
		domain:  domain,
		options: options,
	}
}

// Present fulfills the challenge.Provider.Present interface function
func (p *provider) Present(domain, _, keyAuth string) error {
	_, challengeKey := dns01.GetRecord(domain, keyAuth)
	p.storage().SetChallenge(p.cid, p.domain, challengeKey)
	p.logger().Debugf("setting challengeKey '%s' for CID '%s' and domain '%s'\n", challengeKey, p.cid, p.domain)
	return nil
}

// CleanUp fulfills the challenge.Provider.CleanUp interface function
func (p *provider) CleanUp(_, _, _ string) error {
	p.storage().RemoveChallenge(p.cid, p.domain)
	p.logger().Debugf("removing challengeKey for CID '%s' and domain '%s'\n", p.cid, p.domain)
	return nil
}

// storage returns the storage interface for this instance of provider
func (p *provider) storage() storage.Storage {
	return p.options.Storage
}

// logger returns the logging interface for this instance of provider
func (p *provider) logger() logging.Logger {
	return p.options.Logger
}
