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
	cids            map[string]string
	cidsMu          sync.RWMutex
	dnsChallenges   map[string]string
	dnsChallengesMu sync.RWMutex
}

func New() *Memory {
	return &Memory{
		cids:          make(map[string]string),
		dnsChallenges: make(map[string]string),
	}
}

func (m *Memory) SetCID(id string, cid string) error {
	m.cidsMu.Lock()
	if _, ok := m.cids[id]; ok {
		m.cidsMu.Unlock()
		return storage.ErrAlreadyExists
	}
	m.cids[id] = cid
	m.cidsMu.Unlock()
	return nil
}

func (m *Memory) GetCID(id string) (cid string, ok bool) {
	m.cidsMu.RLock()
	cid, ok = m.cids[id]
	m.cidsMu.RUnlock()
	return
}

func (m *Memory) RemoveCID(id string) error {
	m.cidsMu.Lock()
	if _, ok := m.cids[id]; !ok {
		m.cidsMu.Unlock()
		return storage.ErrNotFound
	}
	delete(m.cids, id)
	m.cidsMu.Unlock()
	return nil
}

func (m *Memory) SetDNSChallenge(cid string, domain string, challenge string) error {
	m.dnsChallengesMu.Lock()
	key := appendDomainToCID(cid, domain)
	if _, ok := m.dnsChallenges[key]; ok {
		m.dnsChallengesMu.Unlock()
		return storage.ErrAlreadyExists
	}
	m.dnsChallenges[key] = challenge
	m.dnsChallengesMu.Unlock()
	return nil
}

func (m *Memory) GetDNSChallenge(cid string, domain string) (challenge string, ok bool) {
	m.dnsChallengesMu.RLock()
	challenge, ok = m.dnsChallenges[appendDomainToCID(cid, domain)]
	m.dnsChallengesMu.RUnlock()
	return
}

func (m *Memory) RemoveDNSChallenge(cid string, domain string) error {
	m.dnsChallengesMu.Lock()
	key := appendDomainToCID(cid, domain)
	if _, ok := m.dnsChallenges[key]; !ok {
		m.dnsChallengesMu.Unlock()
		return storage.ErrNotFound
	}
	delete(m.dnsChallenges, appendDomainToCID(cid, domain))
	m.dnsChallengesMu.Unlock()
	return nil
}

func appendDomainToCID(cid string, domain string) string {
	return utils.JoinStrings(utils.NormalizeDomain(domain), ".", cid)
}
