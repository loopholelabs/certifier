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

// Package dns is responsible for handling all the DNS Requests associated
// with the ACME DNS-01 Challenge
package dns

import (
	"github.com/loopholelabs/certifier/pkg/options"
	"github.com/loopholelabs/certifier/pkg/storage"
	"github.com/loopholelabs/certifier/pkg/utils"
	"github.com/loopholelabs/logging"
	"github.com/miekg/dns"
	"strings"
)

const (
	Network = "udp"
	Mbox    = "admin."

	ShortTTL = 1
	LongTTL  = 86400
	Refresh  = 14400
	Retry    = 3600
	Expire   = 604800
)

// DNS is a DNS Server designed to respond to ACME DNS-01 Challenges
type DNS struct {
	// options contains the options used to configure this instance of DNS
	options *options.Options

	// root is the root domain for this DNS instance
	root string

	// public is the public domain that resolves to this DNS instance
	public string

	// server is the DNS Server for this instance of DNS
	server *dns.Server
}

// New creates a new instance of DNS given a set of configuration
// options, a root domain, and a public domain that resolves to this instance of DNS
func New(root string, public string, opts ...options.Option) *DNS {
	return &DNS{
		options: options.LoadOptions(opts...),
		root:    dns.Fqdn(root),
		public:  dns.Fqdn(public),
	}
}

// Start starts the DNS server on a given address addr
// and then blocks as long as the server is listening.
func (d *DNS) Start(addr string) error {
	d.server = &dns.Server{
		Addr:    addr,
		Net:     Network,
		Handler: dns.HandlerFunc(d.handler),
	}

	d.logger().Infof("starting DNS on address %s with root domain %s\n", addr, d.root)
	return d.server.ListenAndServe()
}

// Shutdown shuts the DNS server down
func (d *DNS) Shutdown() error {
	d.logger().Infof("stopping DNS\n")
	return d.server.Shutdown()
}

// handler handles incoming DNS Queries
func (d *DNS) handler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.RecursionAvailable = false
	m.Rcode = dns.RcodeNameError

	switch r.Opcode {
	case dns.OpcodeQuery:
		m.Authoritative = true
		d.logger().Debugf("received query (ID %d) with questions %+v\n", r.Id, r.Question)
		for _, question := range r.Question {
			question.Name = strings.ToLower(question.Name)
			switch question.Qtype {
			case dns.TypeTXT:
				if ok, domain, cid := d.validTXT(question.Name); ok {
					if challenge, ok := d.storage().GetDNSChallenge(cid, domain); ok {
						txtRecord := d.defaultTXT(question.Name)
						txtRecord.Txt = []string{challenge}
						d.logger().Infof("received TXT query for valid CID '%s' and domain '%s' (ID %d), responding with '%s'\n", cid, domain, r.Id, challenge)
						m.Answer = append(m.Answer, txtRecord)
					} else {
						d.logger().Warnf("received TXT query for unknown CID '%s' and domain '%s' (ID %d)\n", cid, domain, r.Id)
					}
				} else {
					d.logger().Warnf("received TXT query for invalid cid/domain '%s' (ID %d)\n", question.Name, r.Id)
				}
			case dns.TypeNS:
				if d.validNS(question.Name) {
					nsRecord := d.defaultNS(question.Name)
					nsRecord.Ns = d.public
					d.logger().Infof("received NS query for valid domain '%s' (ID %d), responding with '%s'\n", question.Name, r.Id, d.public)
					m.Answer = append(m.Answer, nsRecord)
				} else {
					d.logger().Warnf("received NS query for invalid domain '%s' (ID %d)\n", question.Name, r.Id)
				}
			case dns.TypeSOA:
				if d.validSOA(question.Name) {
					soaRecord := d.defaultSOA(question.Name)
					soaRecord.Ns = d.public
					soaRecord.Mbox = utils.JoinStrings(Mbox, d.public)
					d.logger().Infof("received SOA query for valid domain '%s' (ID %d), responding with NS '%s', Serial %d, and Mbox '%s'\n", question.Name, r.Id, soaRecord.Ns, soaRecord.Serial, soaRecord.Mbox)
					m.Answer = append(m.Answer, soaRecord)
				} else {
					d.logger().Warnf("received SOA query for invalid domain '%s' (ID %d)\n", question.Name, r.Id)
				}
			default:
				d.logger().Warnf("received invalid question type %d (ID %d)\n", question.Qtype, r.Id)
			}
		}
	default:
		d.logger().Warnf("received invalid operation %d (ID %d)\n", r.Opcode, r.Id)
		m.Rcode = dns.RcodeRefused
	}

	if len(m.Answer) > 0 {
		m.Rcode = dns.RcodeSuccess
	}

	err := w.WriteMsg(m)
	if err != nil {
		d.logger().Errorf("error writing DNS response: %s\n", err)
	}
}

// validTXT checks whether the given domain is valid for returning TXT Records
// and also returns the subdomain and the CID (in that order)
func (d *DNS) validTXT(domain string) (bool, string, string) {
	if qualifiers := strings.SplitN(domain, ".", 3); len(qualifiers) == 3 && qualifiers[2] == d.root {
		return true, qualifiers[0], qualifiers[1]
	}
	return false, "", ""
}

// defaultTXT returns a TXT Record with the defaults filled in
func (d *DNS) defaultTXT(domain string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(domain),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    ShortTTL,
		},
	}
}

// validNS checks whether the given domain is valid for returning NS Records
func (d *DNS) validNS(domain string) bool {
	if len(domain) >= len(d.root) && domain[len(domain)-len(d.root):] == d.root {
		return true
	}
	return false
}

// defaultNS returns an NS Record with the defaults filled in
func (d *DNS) defaultNS(domain string) *dns.NS {
	return &dns.NS{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(domain),
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    LongTTL,
		},
	}
}

// validSOA checks whether the given domain is valid for returning SOA Records
func (d *DNS) validSOA(domain string) bool {
	if len(domain) >= len(d.root) && domain[len(domain)-len(d.root):] == d.root {
		return true
	}
	return false
}

// defaultSOA returns an SOA Record with the defaults filled in
func (d *DNS) defaultSOA(domain string) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(domain),
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    LongTTL,
		},
		Refresh: Refresh,
		Retry:   Retry,
		Expire:  Expire,
		Minttl:  LongTTL,
	}
}

// storage returns the storage interface for this instance of DNS
func (d *DNS) storage() storage.Storage {
	return d.options.Storage
}

// logger returns the logging interface for this instance of DNS
func (d *DNS) logger() logging.Logger {
	return d.options.Logger
}
