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

// Package storage contains the storage interface
// that Certifier expects to use
package storage

// Storage is the storage interface that Certifier uses
// to map CIDs with User IDs and work with DNS-01 Challenges
type Storage interface {
	// SetCID sets the CertifierID (CID) for a given ID
	SetCID(id string, cid string)

	// GetCID retrieves the CID for a given ID
	GetCID(id string) (cid string, ok bool)

	// RemoveCID removes the CID for a given ID
	RemoveCID(id string)

	// SetChallenge sets the challenge string given a CID and a domain
	//
	// It is the responsibility of the implementation to normalize the given domain (replace periods with hyphens)
	SetChallenge(cid string, domain string, challenge string)

	// GetChallenge retrieves the challenge string given a CID and a domain
	//
	// It is the responsibility of the implementation to normalize the given domain (replace periods with hyphens)
	GetChallenge(cid string, domain string) (challenge string, ok bool)

	// RemoveChallenge removes the CID for a given ID
	//
	// It is the responsibility of the implementation to normalize the given domain (replace periods with hyphens)
	RemoveChallenge(cid string, domain string)
}
