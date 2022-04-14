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
	"github.com/loopholelabs/certifier/pkg/storage/memory"
	"github.com/loopholelabs/logging"
	"time"
)

var (
	listen string
	root   string
	public string
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
	flag.Parse()

	c := certifier.New(root, public, certifier.WithLogger(logger), certifier.WithStorage(storage))

	storage.SetCID("userid", "testcid")

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	acmeUser := &User{
		Email: "testemail@testemail.com",
		Key:   privateKey,
	}

	acmeConfig := lego.NewConfig(acmeUser)

	acmeConfig.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmeConfig.Certificate.KeyType = certcrypto.RSA4096

	acmeClient, err := lego.NewClient(acmeConfig)
	if err != nil {
		panic(err)
	}

	// This is an API Call to the ACME Directory, which can be slow
	reg, err := acmeClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		panic(err)
	}

	acmeUser.Registration = reg

	go func() {
		time.Sleep(time.Second * 5)
		logger.Infof("Starting Cert Renewal, expecting TXT for _acme-challenge.testdomain.loopholelabs.com to point to testdomain-loopholelabs-com.testcid.%s", root)
		cert, err := c.Renew("userid", "testdomain.loopholelabs.com", acmeClient, privateKey)
		if err != nil {
			panic(err)
		}
		logger.Infof("Certificate Retrieved Successfully: %+v\n", cert)
		logger.Infof("Certificate Contents: %s\n", cert.Certificate)
	}()

	if err := c.Start(listen); err != nil {
		panic(err)
	}
}
