# Certifier
Certifier is a library designed to make it easy to obtain ACME TLS certificates
using the DNS-01 Challenge. Certifier is not designed to work as a standalone-CLI, but instead
it is designed to be embedded within other Golang applications. 

## Architecture
There are two parts to certifier - the DNS Server and the Renewal Server (which we call the renewer). 

The DNS Server is quite simple - it only responds to TXT Record queries for subdomains of a single given root domain.
This means that if the certifier is configured with the root domain `acme.mydomain.com`, it will only respond to TXT queries
for the domains matching `*.*.acme.mydomain.com`. It will also respond to NS Record queries for the root domain and all of its subdomains.

The Renewal Server (the `renewer`) makes use of the [Lego ACME](https://go-acme.github.io/lego) Library to begin and complete `DNS-01` challenges.

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
To actually perform a DNS-01 challenge you must do the following:
1. Create the CNAME record of the form `_acme-challenge.testdomain.com` (if your chosen domain is `testdomain.com`), and point it at `testdomain-com.<CID>.acme.mydomain.com`, replacing all the periods with hyphens (`-`).
2. Start the renewer using the `certifier.Renew` function, passing in your [Lego ACME](https://go-acme.github.io/lego) configuration, your private key, an authorized user ID, and the domain you'd like to obtain a certificate for.
3. Certifier begin the Certificate Request flow and will receive a Challenge Response. It will then begin to serve a TXT record containing the Challenge Response at the domain `testdomain-com.<CID>.acme.mydomain.com`.
4. Certifier will manually verify that the TXT record exists and is valid before proceeding with the certificate request flow. 
6. Let's Encrypt will then look up the TXT Record at `_acme-challenge.testdomain.com` and will be told via the CNAME record you created to instead query the TXT Record at `testdomain-com.<CID>.acme.mydomain.com`. 
7. Let's Encrypt will then query the NS Record of `testdomain-com.<CID>.acme.mydomain.com` and receive the IP address of your Certifier instance. It will then query the TXT Record at `testdomain-com.<CID>.acme.mydomain.com` where your Certifier will respond with the ACME Challenge Response password that was stored during step 3.
8. Let's Encrypt will then return a valid certificate, and Certifier will clean up the TXT Record at `testdomain-com.<CID>.acme.mydomain.com` - but you should leave the CNAME Record for `_acme-challenge.testdomain.com` pointing to your certifier instance for future renewals. 

## Demo Command
There is a very simple demo command 