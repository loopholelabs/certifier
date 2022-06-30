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

// Package acme handles all the interactions with an ACME server when performing a DNS-01 Challenge
package acme

import (
	"crypto/rsa"
	"errors"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/google/uuid"
	"github.com/loopholelabs/certifier/pkg/options"
	"github.com/loopholelabs/certifier/pkg/storage"
	"github.com/loopholelabs/certifier/pkg/utils"
	"github.com/loopholelabs/logging"
)

var (
	// IDNotFoundError is returned when the given ID is not found in the storage
	IDNotFoundError = errors.New("ID not found")
)

// ACME manages ACME DNS-01 Challenges
type ACME struct {
	// options contains the options used to configure this instance of ACME
	options *options.Options
}

// New creates a new instance of ACME given a set of configuration
// options
func New(opts ...options.Option) *ACME {
	return &ACME{
		options: options.LoadOptions(opts...),
	}
}

// RegisterCID registers a CID for a given ID and returns the generated CID
func (a *ACME) RegisterCID(id string) (string, error) {
	cid := uuid.New().String()
	err := a.storage().SetCID(id, cid)
	if err != nil {
		return "", err
	}
	a.logger().Debugf("registered new CID '%s' for ID '%s'\n", cid, id)
	return cid, nil
}

// Renew obtains an SSL Certificate using the DNS-01 Challenge for a given lego.Client and rsa.PrivateKey
func (a *ACME) Renew(id string, domain string, client *lego.Client, privateKey *rsa.PrivateKey) (*certificate.Resource, error) {
	a.logger().Debugf("starting certificate renewal for id '%s' and domain '%s'\n", id, domain)
	cid, ok := a.storage().GetCID(id)
	if !ok {
		return nil, IDNotFoundError
	}

	provider := newProvider(cid, utils.NormalizeDomain(domain), a.options)
	err := client.Challenge.SetDNS01Provider(provider, dns01.AddRecursiveNameservers(a.trustedNameServers()))
	if err != nil {
		return nil, err
	}

	certRequest := certificate.ObtainRequest{
		Domains:    []string{domain},
		Bundle:     false,
		PrivateKey: privateKey,
	}

	return client.Certificate.Obtain(certRequest)
}

// logger returns the logging interface for this instance of ACME
func (a *ACME) logger() logging.Logger {
	return a.options.Logger
}

// storage returns the storage interface for this instance of ACME
func (a *ACME) storage() storage.Storage {
	return a.options.Storage
}

// trustedNameServers returns the trusted nameservers for this instance of ACME
func (a *ACME) trustedNameServers() []string {
	return a.options.TrustedNameServers
}
