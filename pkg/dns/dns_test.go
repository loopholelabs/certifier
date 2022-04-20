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

package dns

import (
	"github.com/loopholelabs/certifier/pkg/options"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	rootDomain   = "example.root.domain"
	publicDomain = "example.public.domain"
)

func TestNew(t *testing.T) {
	t.Parallel()

	d := New(rootDomain, publicDomain)
	assert.Equal(t, dns.Fqdn(rootDomain), d.root)
	assert.Equal(t, dns.Fqdn(publicDomain), d.public)
	assert.Nil(t, d.server)

	assert.Equal(t, options.DefaultLogger, d.options.Logger)
	assert.Equal(t, options.DefaultStorage, d.options.Storage)

	assert.Equal(t, d.options.Logger, d.logger())
	assert.Equal(t, d.options.Storage, d.storage())
}

func TestTXT(t *testing.T) {
	t.Parallel()

	const domain = "default.domain"

	d := New(rootDomain, publicDomain)

	txt := d.defaultTXT(domain)
	assert.Equal(t, dns.Fqdn(domain), txt.Hdr.Name)
	assert.Equal(t, uint16(dns.ClassINET), txt.Hdr.Class)
	assert.Equal(t, dns.TypeTXT, txt.Hdr.Rrtype)
	assert.Equal(t, uint32(ShortTTL), txt.Hdr.Ttl)

	t.Run("valid", func(t *testing.T) {
		ok, domain, cid := d.validTXT("testdomain.cid.example.subdomain.com")
		assert.False(t, ok)
		assert.Empty(t, domain)
		assert.Empty(t, cid)

		ok, domain, cid = d.validTXT(dns.Fqdn("testdomain.cid." + rootDomain))
		assert.True(t, ok)
		assert.Equal(t, "testdomain", domain)
		assert.Equal(t, "cid", cid)

		ok, _, _ = d.validTXT(dns.Fqdn("test.testdomain.cid." + rootDomain))
		assert.False(t, ok)

		ok, _, _ = d.validTXT(dns.Fqdn("test.testdomain.cid." + publicDomain))
		assert.False(t, ok)
	})
}

func TestNS(t *testing.T) {
	t.Parallel()

	const domain = "default.domain"

	d := New(rootDomain, publicDomain)

	ns := d.defaultNS(domain)
	assert.Equal(t, dns.Fqdn(domain), ns.Hdr.Name)
	assert.Equal(t, uint16(dns.ClassINET), ns.Hdr.Class)
	assert.Equal(t, dns.TypeNS, ns.Hdr.Rrtype)
	assert.Equal(t, uint32(LongTTL), ns.Hdr.Ttl)

	t.Run("valid", func(t *testing.T) {
		ok := d.validNS("testdomain.cid.example.subdomain.com")
		assert.False(t, ok)

		ok = d.validNS(dns.Fqdn("testdomain.cid." + rootDomain))
		assert.True(t, ok)

		ok = d.validNS(dns.Fqdn("test.testdomain.cid." + rootDomain))
		assert.True(t, ok)

		ok = d.validNS(dns.Fqdn("test.testdomain.cid." + publicDomain))
		assert.False(t, ok)

		ok = d.validNS(dns.Fqdn("cid." + rootDomain))
		assert.True(t, ok)

		ok = d.validNS(dns.Fqdn(rootDomain))
		assert.True(t, ok)
	})
}

func TestSOA(t *testing.T) {
	t.Parallel()

	const domain = "default.domain"

	d := New(rootDomain, publicDomain)

	soa := d.defaultSOA(domain)
	assert.Equal(t, dns.Fqdn(domain), soa.Hdr.Name)
	assert.Equal(t, uint16(dns.ClassINET), soa.Hdr.Class)
	assert.Equal(t, dns.TypeSOA, soa.Hdr.Rrtype)
	assert.Equal(t, uint32(LongTTL), soa.Hdr.Ttl)
	assert.Equal(t, uint32(Refresh), soa.Refresh)
	assert.Equal(t, uint32(Retry), soa.Retry)
	assert.Equal(t, uint32(Expire), soa.Expire)
	assert.Equal(t, uint32(LongTTL), soa.Minttl)

	t.Run("valid", func(t *testing.T) {
		ok := d.validSOA("testdomain.cid.example.subdomain.com")
		assert.False(t, ok)

		ok = d.validSOA(dns.Fqdn("testdomain.cid." + rootDomain))
		assert.True(t, ok)

		ok = d.validSOA(dns.Fqdn("test.testdomain.cid." + rootDomain))
		assert.True(t, ok)

		ok = d.validSOA(dns.Fqdn("test.testdomain.cid." + publicDomain))
		assert.False(t, ok)

		ok = d.validSOA(dns.Fqdn("cid." + rootDomain))
		assert.True(t, ok)

		ok = d.validSOA(dns.Fqdn(rootDomain))
		assert.True(t, ok)
	})
}
