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

// Package memory is a simple in-memory implementation of the storage.Storage interface

package memory

import (
	"github.com/loopholelabs/certifier/pkg/storage"
	"github.com/loopholelabs/certifier/pkg/utils"
	"sync"
)

var _ storage.Storage = (*Memory)(nil)

type Memory struct {
	cids         map[string]string
	cidsMu       sync.RWMutex
	challenges   map[string]string
	challengesMu sync.RWMutex
}

func New() *Memory {
	return &Memory{
		cids:       make(map[string]string),
		challenges: make(map[string]string),
	}
}

func (m *Memory) SetCID(id string, cid string) {
	m.cidsMu.Lock()
	m.cids[id] = cid
	m.cidsMu.Unlock()
}

func (m *Memory) GetCID(id string) (cid string, ok bool) {
	m.cidsMu.RLock()
	cid, ok = m.cids[id]
	m.cidsMu.RUnlock()
	return
}

func (m *Memory) RemoveCID(id string) {
	m.cidsMu.Lock()
	delete(m.cids, id)
	m.cidsMu.Unlock()
}

func (m *Memory) SetChallenge(cid string, domain string, challenge string) {
	m.challengesMu.Lock()
	m.challenges[appendDomainToCID(cid, domain)] = challenge
	m.challengesMu.Unlock()
}

func (m *Memory) GetChallenge(cid string, domain string) (challenge string, ok bool) {
	m.challengesMu.RLock()
	challenge, ok = m.challenges[appendDomainToCID(cid, domain)]
	m.challengesMu.RUnlock()
	return
}

func (m *Memory) RemoveChallenge(cid string, domain string) {
	m.challengesMu.Lock()
	delete(m.challenges, appendDomainToCID(cid, domain))
	m.challengesMu.Unlock()
}

func appendDomainToCID(cid string, domain string) string {
	return utils.JoinStrings(utils.NormalizeDomain(domain), ".", cid)
}
