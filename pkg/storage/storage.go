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

package storage

type Storage interface {
	SetCID(id string, cid string)
	GetCID(id string) (cid string, ok bool)
	RemoveCID(id string)

	SetChallenge(cid string, domain string, challenge string)
	GetChallenge(cid string, domain string) (challenge string, ok bool)
	RemoveChallenge(cid string, domain string)
}
