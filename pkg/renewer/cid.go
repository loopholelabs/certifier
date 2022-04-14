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
	"github.com/go-acme/lego/v4/challenge/dns01"
)

type cidRenewer struct {
	r   *Renewer
	cid string
}

func newCIDRenewer(r *Renewer, cid string) *cidRenewer {
	return &cidRenewer{
		r:   r,
		cid: cid,
	}
}

func (c *cidRenewer) Present(domain, _, keyAuth string) error {
	fqdn, challenge := dns01.GetRecord(domain, keyAuth)
	c.r.storage.SetChallenge(c.cid, fqdn, challenge)
	return nil
}

func (c *cidRenewer) CleanUp(domain, _, keyAuth string) error {
	fqdn, _ := dns01.GetRecord(domain, keyAuth)
	c.r.storage.RemoveChallenge(c.cid, fqdn)
	return nil
}
