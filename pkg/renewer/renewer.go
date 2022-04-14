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

package renewer

import (
	"crypto/rsa"
	"errors"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/google/uuid"
	"github.com/loopholelabs/certifier/internal/utils"
	"github.com/loopholelabs/certifier/pkg/storage"
	"github.com/loopholelabs/logging"
)

var (
	IDNotFoundError = errors.New("ID not found")
)

type Renewer struct {
	trustedNameservers []string
	storage            storage.Storage
	logger             logging.Logger
}

func New(trustedNameServers []string, storage storage.Storage, logger logging.Logger) *Renewer {
	return &Renewer{
		trustedNameservers: trustedNameServers,
		storage:            storage,
		logger:             logger,
	}
}

func (r *Renewer) RegisterCID(id string) (cid string) {
	cid = uuid.New().String()
	r.storage.SetCID(id, cid)
	return
}

func (r *Renewer) Renew(id string, domain string, client *lego.Client, privateKey *rsa.PrivateKey) (*certificate.Resource, error) {
	cid, ok := r.storage.GetCID(id)
	if !ok {
		return nil, IDNotFoundError
	}

	cidr := newCIDRenewer(r, cid, utils.NormalizeDomain(domain))
	var err error
	if r.trustedNameservers != nil {
		err = client.Challenge.SetDNS01Provider(cidr, dns01.AddRecursiveNameservers(r.trustedNameservers))
	} else {
		err = client.Challenge.SetDNS01Provider(cidr)
	}
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
