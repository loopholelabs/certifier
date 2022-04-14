# Certifier
Certifier is a library designed to make it easy to obtain ACME TLS certificates
using the DNS-01 Challenge. Certifier is not designed to work as a standalone-CLI, but instead
it is designed to be embedded within other Golang applications. 

There are two parts to certifier - the DNS Server and the Renewal Server (which we call the renewer). 

The DNS Server is quite simple - it only responds to TXT Record queries for subdomains of a single given root domain.
This means that if the certifier is configured with the root domain `acme.mydomain.com`, it will only respond to TXT queries
for the domains matching `*.*.acme.mydomain.com`.

The Renewal Server (the `renewer`) makes use of the [Lego ACME](https://go-acme.github.io/lego) Library to begin and complete `DNS-01` challenges.

In order to use certifier to obtain a TLS Certificate using an ACME provider like
Let's Encrypt, you must first configure and run Certifier somewhere that is accessible from
the public internet. 

Let's say you configure certifier for the domain `acme.mydomain.com`. The first thing you'll need to do is create the proper NS Record 
to point DNS requests to certifier. We want to forward NS Queries of the form `*.*.acme.mydomain.com` to your certifier instance.

Something like `*.*.acme.mydomain.com NS <certifier IP>` should work perfectly.

Next, you'll need to register a user with Certifier. You will need to do this for every new user that wants to use certifier to obtain certificates.

To do this, you must provide a unique ID for the user, and it is your responsibility to guarantee that the correct user is requesting certificates using their own ID. 
Once you have a unique ID for your user, you can register them with Certifier by doing `certifier.RegisterCID`. This will map a certifier identifier (the `CID`)
to your user's ID. 

Your user should then create a CNAME record of the form `_acme-challenge.testdomain.com` pointing to `testdomain-com.<CID>.acme.mydomain.com`. You must replace 
the periods in your root domain (`testdomain.com`) with hyphens (`-`), and create a CNAME record that points to `<root domain with periods replaced>.<cid returned by certifier>.acme.mydomain.com`. 
Remember that `acme.mydomain.com` is the domain where your certifier instance is running. 

and create a wildcard NS Record for a domain you control that points to Certifier.


At this point Certifier is ready to respond to DNS-01 Challenges.

To actually perform a DNS-01 challenge you must do the following:
1. Pick a unique domain that is a subset of the wildcard NS record you created when setting up Certifier. For example, if you'd like to create a certificate for the domain `testdomain.com`, you can pick the unique domain `testdomain-com.acme.mydomain.com`.
2. Now create a CNAME record of the form `_acme-challenge.testdomain.com` that points to the unique domain you picked (`testdomain-com.acme.mydomain.com`). Something like `_acme-challenge.testdomain.com CNAME testdomain-com.acme.mydomain.com` should work perfectly
3. Begin the DNS-01 Challenge and store the ACME Challenge Response Password inside Certifier at the unique domain you picked `testdomain-com.acme.mydomain.com`). 
4. Let's Encrypt will then look up the TXT Record at `_acme-challenge.testdomain.com` and will be told via the CNAME record you created to instead query the TXT Record at `testdomain-com.acme.mydomain.com`. 
5. Let's Encrypt will then query the NS Record of `testdomain-com.acme.mydomain.com` and receive the IP address of your Certifier instance. It will then query the TXT Record at `testdomain-com.acme.mydomain.com` where your Certifier will respond with the ACME Challenge Response password that was stored during step 3.
6. Let's Encrypt will then return a valid certificate, and you are free to then clean up the TXT Record at `testdomain-com.acme.mydomain.com` - but you should leave the CNAME Record for `_acme-challenge.testdomain.com` pointing to your certifier instance.
