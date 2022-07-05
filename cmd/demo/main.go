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

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/loopholelabs/certifier"
	"github.com/loopholelabs/certifier/internal/memory"
	"github.com/loopholelabs/certifier/pkg/options"
	"github.com/loopholelabs/certifier/pkg/utils"
	"github.com/loopholelabs/logging"
	"os"
	"time"
)

const (
	userID = "userid"
	CID    = "testcid"
)

var (
	listen    string
	root      string
	public    string
	directory string
	email     string
	domain    string
)

type User struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	Key          *rsa.PrivateKey        `json:"key"`
}

func (u *User) GetEmail() string {
	return u.Email
}
func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

func main() {
	logger := logging.NewConsoleLogger()
	logger.SetLevel(logging.DebugLevel)

	storage := memory.New()

	flag.StringVar(&listen, "listen", "", "set the listen address for certifier")
	flag.StringVar(&root, "root", "", "set the root domain for certifier")
	flag.StringVar(&public, "public", "", "set the publicly resolvable domain that resolves to certifier")
	flag.StringVar(&directory, "directory", "", "set the ACME directory URL")
	flag.StringVar(&email, "email", "", "set the email for your ACME registration")
	flag.StringVar(&domain, "domain", "", "set the domain to obtain a certificate for")
	flag.Parse()

	if listen == "" || root == "" || public == "" || directory == "" || email == "" || domain == "" {
		panic("all required command line args must be filled in: --listen, --root, --public, --directory, --email, --domain")
	}

	logger.Importantf("In order for this demo to work, you must have this instance of Certifier publicly available on port 53 and accessible on the domain '%s' (via an A record)\n", public)
	logger.Importantf("You must also have an NS record for '%s' pointing to '%s'\n", root, public)
	logger.Importantf("And finally, you must have a CNAME record for '_acme-challenge.%s' pointing to '%s.%s.%s'\n", domain, utils.NormalizeDomain(domain), CID, root)
	logger.Importantf("Without these records, this demo will fail.\n")

	c := certifier.New(root, public, options.WithLogger(logger), options.WithStorage(storage))

	// normally you would use c.ACME().RegisterCID, but we want to use a hard-coded CID, not a randomly generated one so we are
	// setting the value in storage manually
	err := storage.SetCID(userID, CID)
	if err != nil {
		panic(err)
	}

	clientPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	certificatePrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	acmeUser := &User{
		Email: email,
		Key:   clientPrivateKey,
	}

	acmeConfig := lego.NewConfig(acmeUser)

	acmeConfig.CADirURL = directory
	acmeConfig.Certificate.KeyType = certcrypto.RSA4096

	acmeClient, err := lego.NewClient(acmeConfig)
	if err != nil {
		panic(err)
	}

	reg, err := acmeClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		panic(err)
	}

	acmeUser.Registration = reg

	go func() {
		time.Sleep(time.Second * 2)
		logger.Infof("Starting Cert Renewal, expecting TXT Record for for '_acme-challenge.%s' to point to '%s.%s.%s", domain, utils.NormalizeDomain(domain), CID, root)
		cert, err := c.ACME().RenewDNS(userID, domain, acmeClient, certificatePrivateKey)
		if err != nil {
			panic(err)
		}
		logger.Infof("Certificate Contents: \n%s\n\n", cert.Certificate)
		err = c.Shutdown()
		if err != nil {
			panic(err)
		}
		os.Exit(0)
	}()

	if err := c.Start(listen); err != nil {
		panic(err)
	}
}
