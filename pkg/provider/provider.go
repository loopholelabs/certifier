/*
	Copyright 2022 Loophole Labs

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		   http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package provider

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/loopholelabs/certifier/pkg/options"
	"github.com/loopholelabs/certifier/pkg/storage"
	"github.com/loopholelabs/logging"
)

var _ challenge.Provider = (*Provider)(nil)

// Provider satisfies the challenge.Provider interface for renewing
// ACME Certificates using the DNS-01 Challenge
type Provider struct {
	// options contains the options used to configure this instance of Provider
	options *options.Options

	// cid is the CID for this Provider
	cid string

	// domain is the domain for this instance of Provider
	domain string
}

func New(cid string, domain string, options *options.Options) *Provider {
	return &Provider{
		cid:     cid,
		domain:  domain,
		options: options,
	}
}

// Present fulfills the challenge.Provider.Present interface function
func (p *Provider) Present(domain, _, keyAuth string) error {
	_, challengeKey := dns01.GetRecord(domain, keyAuth)
	err := p.storage().SetDNSChallenge(p.cid, p.domain, challengeKey)
	if err != nil {
		return err
	}
	p.logger().Debugf("setting challengeKey '%s' for CID '%s' and domain '%s'\n", challengeKey, p.cid, p.domain)
	return nil
}

// CleanUp fulfills the challenge.Provider.CleanUp interface function
func (p *Provider) CleanUp(_, _, _ string) error {
	err := p.storage().RemoveDNSChallenge(p.cid, p.domain)
	if err != nil {
		return err
	}
	p.logger().Debugf("removing challengeKey for CID '%s' and domain '%s'\n", p.cid, p.domain)
	return nil
}

// storage returns the storage interface for this instance of Provider
func (p *Provider) storage() storage.Storage {
	return p.options.Storage
}

// logger returns the logging interface for this instance of Provider
func (p *Provider) logger() logging.Logger {
	return p.options.Logger
}
