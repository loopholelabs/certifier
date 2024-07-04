# Certifier

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-brightgreen.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Discord](https://dcbadge.vercel.app/api/server/JYmFhtdPeu?style=flat)](https://loopholelabs.io/discord)
[![go-doc](https://godoc.org/github.com/loopholelabs/certifier?status.svg)](https://godoc.org/github.com/loopholelabs/certifier)

Certifier is a library designed to make it easy to obtain ACME TLS certificates
using the DNS-01 Challenge. Certifier is not designed to work as a standalone-CLI, but instead
it is designed to be embedded within other Golang applications.

## Architecture

There are two parts to certifier - the DNS Server and the ACME manager.

The DNS Server is quite simple - it only responds to TXT Record queries for subdomains of a single given root domain.
This means that if the certifier is configured with the root domain `acme.mydomain.com`, it will only respond to TXT queries
for the domains matching `*.*.acme.mydomain.com`. It will also respond to NS Record queries and SOA Record Queries for the root domain
and all of its subdomains.

The ACME manager makes use of the [Lego ACME](https://go-acme.github.io/lego) Library to begin and complete `DNS-01` challenges.

## Requirements

In order to use certifier to obtain a TLS Certificate using an ACME provider like
Let's Encrypt, you must first configure and run Certifier somewhere that is accessible from
the public internet.

Let's say you configure certifier for the domain `acme.mydomain.com`. The first thing you'll need to do is create the proper A and NS Records
to point DNS requests to certifier. We want to forward NS Queries of the form `*.*.acme.mydomain.com` to your certifier instance, so you first need to create an A record
for `certifier.mydomain.com` that points to the IP of your certifier instance.

Something like `certifier.mydomain.com A <certifier IP>` should work great.

Next you need to create an NS record for `acme.mydomain.com` setting your certifier instance as the authoritive name server. A record like `acme.mydomain.com NS certifier.mydomain.com` should work perfectly.

Next, you'll need to register a user with Certifier. You will need to do this for every new user that wants to use certifier to obtain certificates.

To do this, you must provide a unique ID for the user, and it is your responsibility to guarantee that the correct user is requesting certificates using their own ID.
Once you have a unique ID for your user, you can register them with Certifier by doing `certifier.RegisterCID`. This will map a certifier identifier (the `CID`)
to your user's ID.

Your user should then create a CNAME record of the form `_acme-challenge.testdomain.com` pointing to `testdomain-com.<CID>.acme.mydomain.com`. You must replace
the periods in your root domain (`testdomain.com`) with hyphens (`-`), and create a CNAME record that points to `<root domain with periods replaced>.<cid returned by certifier>.acme.mydomain.com`.
Remember that `acme.mydomain.com` is the domain who's name server is your certifier instance.

### Certificate Request Flow

During an actual Certificate Request Flow, the following happens:

1. Create the CNAME record of the form `_acme-challenge.testdomain.com` (if your chosen domain is `testdomain.com`), and point it at `testdomain-com.<CID>.acme.mydomain.com`, replacing all the periods with hyphens (`-`).
2. Start the renewer using the `certifier.Renew` function, passing in your [Lego ACME](https://go-acme.github.io/lego) configuration, your private key, an authorized user ID, and the domain you'd like to obtain a certificate for.
3. Certifier begin the Certificate Request flow and will receive a Challenge Response. It will then begin to serve a TXT record containing the Challenge Response at the domain `testdomain-com.<CID>.acme.mydomain.com`.
4. Certifier will manually verify that the TXT record exists and is valid before proceeding with the certificate request flow.
5. Let's Encrypt will then look up the TXT Record at `_acme-challenge.testdomain.com` and will be told via the CNAME record you created to instead query the TXT Record at `testdomain-com.<CID>.acme.mydomain.com`.
6. Let's Encrypt will then query the NS Record of `testdomain-com.<CID>.acme.mydomain.com` and receive the IP address of your Certifier instance. It will then query the TXT Record at `testdomain-com.<CID>.acme.mydomain.com` where your Certifier will respond with the ACME Challenge Response password that was stored during step 3.
7. Let's Encrypt will then return a valid certificate, and Certifier will clean up the TXT Record at `testdomain-com.<CID>.acme.mydomain.com` - but you should leave the CNAME Record for `_acme-challenge.testdomain.com` pointing to your certifier instance for future renewals.

## Demo Command

There is a very simple demo application in this repo that will demonstrate end-to-end how to use Certifier + [Lego ACME](https://go-acme.github.io/lego) to receive an SSL Certificate from Let's Encrypt.

It must be run on a server that is routable from the internet (a simple Digital Ocean VPS should work nicely), and it will get a valid SSL Certificate for a given domain.

You must first pick 3 separate domains:

1. The domain that will point to your certifier instance (the server that certifier is running on, which is routable from the public internet) - as an example, we will use `certifier.loopholelabs.com`
2. A certifier root domain - this will be used to tell let's encrypt which DNS Server it should query for a valid DNS-01 Challenge (in our case, that DNS Server is certifier) - as an example, we will use `acme.loopholelabs.com`
3. The domain what you will obtain an SSL Certificate for - as an example, we will use `testdomain.loopholelabs.com`.

### Set Up

To set up the demo command, begin by spinning up a VPS or any sort of server that is routable from the public internet. You'll want to make sure port `53` is open for `UDP` traffic. Note the public IP for this server - in this example, we will use `10.0.0.50`.

1. Start by creating an `A` record for the first domain you picked that points to the public IP of your server - we picked `certifier.loopholelabs.com` so we'll create an `A` record that looks something like `certifier.loopholelabs.com A 10.0.0.50`
2. Next, create the `NS` record that instructs let's encrypt to use your certifier instance as the DNS Server for DNS-01 Challenges - we picked `acme.loopholelabs.com` as our root domain, so we'll create an `NS` record that looks something like `acme.loopholelabs.com NS certifier.loopholelabs.com`
3. Replace all the periods in the domain you'll be obtaining an SSL certificate for with hyphens (`-`) - we will call this the normalized domain - we picked `testdomain.loopholelabs.com` so our normalized domain would be `testdomain-loopholelabs-com`.
4. For this demo application, the `CID` will always be `testcid` - however during real use of Certifier this will be an autogenerated UUID that will map to a user ID.
5. Finally, create a `CNAME` record that points to the root domain you chose. The CNAME record should be of the form `<normalized domain>.<CID>.<root domain>` - we picked `testdomain-loopholelabs-com` and `acme.loopholelabs.com`, so we'll create a `CNAME` record that looks something like `testdomain-loopholelabs-com.testcid.acme.loopholelabs.com`.

## Running the Demo Command

Once you've completed the setup for running the Demo Command, you can run it like so:

```bash
go run cmd/demo/main.go --listen <listen address> --root <root domain> --public <certifier domain> --email <your email> --domain <the domain you want to obtain an SSL certificate for> --directory <acme directory URL>
```

For this example, a working command would be

```bash
go run cmd/demo/main.go --listen 0.0.0.0:53 --root acme.loopholelabs.com --public certifier.loopholelabs.com --email testemail@loopholelabs.io --domain testdomain.loopholelabs.com --directory https://acme-staging-v02.api.letsencrypt.org/directory
```

We recommend testing with the Let's Encrypt Staging Directory First. It may take up to 24 hours for your DNS Records to propagate before you can run the Demo Command.

## Contributing

Bug reports and pull requests are welcome on GitHub at [https://github.com/loopholelabs/certifier][gitrepo]. For more
contribution information check
out [the contribution guide](https://github.com/loopholelabs/certifier/blob/master/CONTRIBUTING.md).

## License

The Certifier project is available as open source under the terms of
the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Code of Conduct

Everyone interacting in the Certifier project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md).

## Project Managed By:

[![https://loopholelabs.io][loopholelabs]](https://loopholelabs.io)

[gitrepo]: https://github.com/loopholelabs/certifier
[loopholelabs]: https://cdn.loopholelabs.io/loopholelabs/LoopholeLabsLogo.svg
[loophomepage]: https://loopholelabs.io
