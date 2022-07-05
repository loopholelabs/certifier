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

// Package certifier makes it easy to spin up a dns.DNS and an acme.ACME instance together
package certifier

import (
	"github.com/loopholelabs/certifier/pkg/acme"
	"github.com/loopholelabs/certifier/pkg/dns"
	"github.com/loopholelabs/certifier/pkg/options"
)

// Certifier packages up a dns.DNS instance and an acme.ACME instance to make it easier to work with both of them
type Certifier struct {
	// dns is the dns.DNS instance for this instance of Certifier
	dns *dns.DNS

	// acme is the acme.ACME instance for this instance of Certifier
	acme *acme.ACME
}

// New creates a new instance of Certifier
func New(root string, public string, opts ...options.Option) *Certifier {
	d := dns.New(root, public, opts...)
	a := acme.New(opts...)
	return &Certifier{
		dns:  d,
		acme: a,
	}
}

// Start starts an instance of Certifier given an address
func (c *Certifier) Start(addr string) error {
	return c.dns.Start(addr)
}

// Shutdown shuts down an instance of Certifier
func (c *Certifier) Shutdown() error {
	return c.dns.Shutdown()
}

// ACME returns the acme.ACME instance for this instance of Certifier
func (c *Certifier) ACME() *acme.ACME {
	return c.acme
}
