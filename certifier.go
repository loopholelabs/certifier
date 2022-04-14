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

package certifier

import (
	"crypto/rsa"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/loopholelabs/certifier/internal/utils"
	"github.com/loopholelabs/certifier/pkg/renewer"
	"github.com/loopholelabs/certifier/pkg/storage"
	"github.com/loopholelabs/logging"
	"github.com/miekg/dns"
	"strings"
)

const (
	Network = "udp"
)

type Certifier struct {
	root    string
	public  string
	serial  uint32
	server  *dns.Server
	renewer *renewer.Renewer
	storage storage.Storage
	logger  logging.Logger
}

func New(root string, public string, serial uint32, opts ...Option) *Certifier {
	options := loadOptions(opts...)

	if root[len(root)-1] != '.' {
		root += "."
	}

	return &Certifier{
		root:    root,
		public:  dns.Fqdn(public),
		serial:  serial,
		renewer: renewer.New(options.TrustedNameServers, options.Storage, options.Logger),
		storage: options.Storage,
		logger:  options.Logger,
	}
}

func (c *Certifier) Start(addr string) error {
	server := &dns.Server{
		Addr:    addr,
		Net:     Network,
		Handler: dns.HandlerFunc(c.handler),
	}

	c.Logger().Infof("starting certifier on address %s with root domain %s\n", addr, c.root)
	return server.ListenAndServe()
}

func (c *Certifier) RegisterCID(id string) string {
	cid := c.renewer.RegisterCID(id)
	c.Logger().Debugf("registered new CID '%s' for ID '%s'\n", cid, id)
	return cid
}

func (c *Certifier) Renew(id string, domain string, client *lego.Client, privateKey *rsa.PrivateKey) (*certificate.Resource, error) {
	c.Logger().Debugf("starting certificate renewal for id %s and domain %s\n", id, domain)
	cert, err := c.renewer.Renew(id, domain, client, privateKey)
	if err != nil {
		c.Logger().Errorf("error while renewing certificate for id %s and domain %s: %s\n", id, domain, err)
	} else {
		c.Logger().Infof("successfully renewed certificate for id %s and domain %s\n", id, domain)
	}

	return cert, err
}

func (c *Certifier) handler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.RecursionAvailable = true

	switch r.Opcode {
	case dns.OpcodeQuery:
		c.Logger().Debugf("received query (ID %d) with questions %+v\n", r.Id, r.Question)
		m.Answer, m.Rcode = c.handleQuestions(r)
		m.Authoritative = true
	default:
		c.Logger().Warnf("received invalid operation %d (ID %d)\n", r.Opcode, r.Id)
		m.Rcode = dns.RcodeRefused
	}

	_ = w.WriteMsg(m)
}

func (c *Certifier) handleQuestions(r *dns.Msg) (answers []dns.RR, rcode int) {
	for _, question := range r.Question {
		question.Name = strings.ToLower(question.Name)
		switch question.Qtype {
		case dns.TypeTXT:
			if qualifiers := strings.SplitN(question.Name, ".", 3); len(qualifiers) == 3 && qualifiers[2] == c.root {
				if challenge, ok := c.storage.GetChallenge(qualifiers[1], qualifiers[0]); ok {
					txtRecord := &dns.TXT{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn(question.Name),
							Rrtype: dns.TypeTXT,
							Class:  dns.ClassINET,
							Ttl:    1,
						},
						Txt: []string{challenge},
					}
					c.Logger().Infof("received TXT query for valid CID '%s' and domain '%s' (ID %d), responding with '%s'\n", qualifiers[1], qualifiers[0], r.Id, challenge)
					answers = append(answers, txtRecord)
					return
				} else {
					c.Logger().Warnf("received TXT query for unknown CID '%s' and domain '%s' (ID %d)\n", qualifiers[1], qualifiers[0], r.Id)
				}
			} else {
				c.Logger().Warnf("received TXT query for invalid cid/domain '%s' (ID %d)\n", question.Name, r.Id)
			}
		case dns.TypeNS:
			if question.Name == c.root {
				nsRecord := &dns.NS{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(question.Name),
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
						Ttl:    86400,
					},
					Ns: c.public,
				}
				c.Logger().Infof("received NS query for valid domain '%s' (ID %d), responding with '%s'\n", question.Name, r.Id, c.public)
				answers = append(answers, nsRecord)
				return
			} else if qualifiers := strings.SplitN(question.Name, ".", 2); len(qualifiers) == 2 && qualifiers[1] == c.root {
				nsRecord := &dns.NS{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(question.Name),
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
						Ttl:    86400,
					},
					Ns: c.public,
				}
				c.Logger().Infof("received NS query for valid domain '%s' (ID %d), responding with '%s'\n", question.Name, r.Id, c.public)
				answers = append(answers, nsRecord)
				return
			} else if qualifiers = strings.SplitN(question.Name, ".", 3); len(qualifiers) == 3 && qualifiers[2] == c.root {
				nsRecord := &dns.NS{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(question.Name),
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
						Ttl:    86400,
					},
					Ns: c.public,
				}
				c.Logger().Infof("received NS query for valid domain '%s' (ID %d), responding with '%s'\n", question.Name, r.Id, c.public)
				answers = append(answers, nsRecord)
				return
			} else {
				c.Logger().Warnf("received NS query for invalid domain '%s' (ID %d)\n", question.Name, r.Id)
			}
		case dns.TypeSOA:
			if question.Name == c.root {
				soaRecord := &dns.SOA{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(question.Name),
						Rrtype: dns.TypeSOA,
						Class:  dns.ClassINET,
						Ttl:    86400,
					},
					Ns:      c.public,
					Mbox:    utils.JoinStrings("admin.", c.public),
					Serial:  c.serial,
					Refresh: 14400,
					Retry:   3600,
					Expire:  604800,
					Minttl:  86400,
				}
				c.Logger().Infof("received SOA query for valid domain '%s' (ID %d), responding with NS '%s', Serial %d, and Mbox '%s'\n", question.Name, r.Id, soaRecord.Ns, soaRecord.Serial, soaRecord.Mbox)
				answers = append(answers, soaRecord)
				return
			} else if qualifiers := strings.SplitN(question.Name, ".", 2); len(qualifiers) == 2 && qualifiers[1] == c.root {
				soaRecord := &dns.SOA{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(question.Name),
						Rrtype: dns.TypeSOA,
						Class:  dns.ClassINET,
						Ttl:    86400,
					},
					Ns:      c.public,
					Mbox:    utils.JoinStrings("admin.", c.public),
					Serial:  c.serial,
					Refresh: 14400,
					Retry:   3600,
					Expire:  604800,
					Minttl:  86400,
				}
				c.Logger().Infof("received SOA query for valid domain '%s' (ID %d), responding with NS '%s', Serial %d, and Mbox '%s'\n", question.Name, r.Id, soaRecord.Ns, soaRecord.Serial, soaRecord.Mbox)
				answers = append(answers, soaRecord)
				return
			} else if qualifiers = strings.SplitN(question.Name, ".", 3); len(qualifiers) == 3 && qualifiers[2] == c.root {
				soaRecord := &dns.SOA{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(question.Name),
						Rrtype: dns.TypeSOA,
						Class:  dns.ClassINET,
						Ttl:    86400,
					},
					Ns:      c.public,
					Mbox:    utils.JoinStrings("admin.", c.public),
					Serial:  c.serial,
					Refresh: 14400,
					Retry:   3600,
					Expire:  604800,
					Minttl:  86400,
				}
				c.Logger().Infof("received SOA query for valid domain '%s' (ID %d), responding with NS '%s', Serial %d, and Mbox '%s'\n", question.Name, r.Id, soaRecord.Ns, soaRecord.Serial, soaRecord.Mbox)
				answers = append(answers, soaRecord)
				return
			} else {
				c.Logger().Warnf("received SOA query for invalid domain '%s' (ID %d)\n", question.Name, r.Id)
			}
		default:
			c.Logger().Warnf("received invalid question type %d (ID %d)\n", question.Qtype, r.Id)
		}
	}
	return nil, dns.RcodeNameError
}

func (c *Certifier) Logger() logging.Logger {
	return c.logger
}
