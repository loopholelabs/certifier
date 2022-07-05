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
	"crypto"
	"crypto/rsa"
	"github.com/go-acme/lego/v4/registration"
)

type user struct {
	email        string
	registration *registration.Resource
	privateKey   *rsa.PrivateKey
}

func (u *user) GetEmail() string {
	return u.email
}
func (u *user) GetRegistration() *registration.Resource {
	return u.registration
}
func (u *user) GetPrivateKey() crypto.PrivateKey {
	return u.privateKey
}

//func TestDNSChallenge(t *testing.T) {
//	alternateRoots := 0
//	chainLength := 1
//
//	logger := log.New(os.Stdout, "Pebble ", log.LstdFlags)
//	db := db.NewMemoryStore()
//	ca := ca.New(logger, db, "", alternateRoots, chainLength, 0)
//	va := va.New(logger, 15000, 16000, false, "127.0.0.1:5053")
//
//	wfeImpl := wfe.New(logger, db, va, ca, false, false)
//	muxHandler := wfeImpl.Handler()
//
//	logger.Printf("Listening on: %s\n", "0.0.0.0:15000")
//	logger.Printf("ACME directory available at: https://%s%s", "localhost:15000", wfe.DirectoryPath)
//
//	var wg sync.WaitGroup
//
//	server := http.Server{
//		Addr:    "0.0.0.0:15000",
//		Handler: muxHandler,
//	}
//
//	wg.Add(1)
//	go func() {
//		err := server.ListenAndServeTLS("testdata/certs/localhost.pem", "testdata/certs/localhost.key")
//		assert.NoError(t, err)
//		wg.Done()
//	}()
//
//	certifier := New("acme.localhost", "localhost", options.WithTrustedNameservers([]string{"127.0.0.1:5053"}))
//
//	wg.Add(1)
//	go func() {
//		err := certifier.Start("0.0.0.0:53")
//		assert.NoError(t, err)
//		wg.Done()
//	}()
//
//	ID := "TEST"
//	CID, err := certifier.RegisterCID(ID)
//	assert.NoError(t, err)
//
//	dnsServer := &dns.Server{
//		Addr: "0.0.0.0:5053",
//		Net:  "udp",
//		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
//			m := new(dns.Msg)
//			m.SetReply(r)
//			m.Compress = false
//			m.RecursionAvailable = false
//			m.Rcode = dns.RcodeSuccess
//
//			switch r.Opcode {
//			case dns.OpcodeQuery:
//				m.Authoritative = true
//				for _, question := range r.Question {
//					question.Name = strings.ToLower(question.Name)
//					switch question.Qtype {
//					case dns.TypeSOA:
//						soaRecord := &dns.SOA{
//							Hdr: dns.RR_Header{
//								Name:   dns.Fqdn(question.Name),
//								Rrtype: dns.TypeSOA,
//								Class:  dns.ClassINET,
//								Ttl:    86400,
//							},
//							Refresh: 14400,
//							Retry:   3600,
//							Expire:  604800,
//							Minttl:  86400,
//							Ns:      "localhost.",
//							Mbox:    "hostmaster.localhost.",
//						}
//						m.Answer = append(m.Answer, soaRecord)
//						t.Logf("received SOA query for domain '%s' (ID %d), responding with NS '%s', Serial %d, and Mbox '%s'\n", question.Name, r.Id, soaRecord.Ns, soaRecord.Serial, soaRecord.Mbox)
//					case dns.TypeNS:
//						nsRecord := &dns.NS{
//							Hdr: dns.RR_Header{
//								Name:   dns.Fqdn(question.Name),
//								Rrtype: dns.TypeNS,
//								Class:  dns.ClassINET,
//								Ttl:    86400,
//							},
//							Ns: "localhost.",
//						}
//						m.Answer = append(m.Answer, nsRecord)
//						t.Logf("received NS query for valid domain '%s' (ID %d), responding with '%s'\n", question.Name, r.Id, "localhost.")
//					default:
//						target := "localhost." + CID + ".acme.localhost"
//						m.Answer = append(m.Answer, &dns.CNAME{
//							Hdr: dns.RR_Header{
//								Name:   dns.Fqdn(question.Name),
//								Rrtype: dns.TypeCNAME,
//								Class:  dns.ClassINET,
//								Ttl:    1,
//							},
//							Target: dns.Fqdn(target),
//						})
//						t.Logf("received query for domain '%s' (TYPE %d, ID %d), responding with CNAME '%s'\n", question.Name, question.Qtype, r.Id, target)
//					}
//				}
//			default:
//				t.Logf("received invalid operation %d (ID %d)\n", r.Opcode, r.Id)
//				m.Rcode = dns.RcodeRefused
//			}
//
//			err := w.WriteMsg(m)
//			if err != nil {
//				t.Logf("error writing DNS response: %s\n", err)
//			}
//		}),
//	}
//
//	wg.Add(1)
//	go func() {
//		err := dnsServer.ListenAndServe()
//		assert.NoError(t, err)
//		wg.Done()
//	}()
//
//	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
//	assert.NoError(t, err)
//
//	u := &user{
//		email:      "test@test.com",
//		privateKey: privateKey,
//	}
//
//	acmeConfig := lego.NewConfig(u)
//
//	acmeConfig.CADirURL = "https://localhost:15000/dir"
//	acmeConfig.Certificate.KeyType = certcrypto.RSA4096
//	acmeConfig.HTTPClient = &http.Client{
//		Transport: &http.Transport{
//			TLSClientConfig: &tls.Config{
//				InsecureSkipVerify: true,
//			},
//		},
//	}
//
//	client, err := lego.NewClient(acmeConfig)
//	assert.NoError(t, err)
//
//	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
//	assert.NoError(t, err)
//
//	u.registration = reg
//
//	certPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
//	assert.NoError(t, err)
//
//	cert, err := certifier.ACME().RenewDNS(ID, "localhost", client, certPrivateKey)
//	assert.NoError(t, err)
//	_ = cert
//
//	err = dnsServer.Shutdown()
//	assert.NoError(t, err)
//
//	err = certifier.Shutdown()
//	assert.NoError(t, err)
//
//	err = server.Shutdown(context.Background())
//	assert.NoError(t, err)
//
//	wg.Wait()
//}
