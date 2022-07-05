# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.3.2] - 2022-07-05

### Fixes

- Fixing major bug in DNS server that would always return an `NXDOMAIN` error regardless of whether the domain was actually valid

### Changes

- Replacing the `RegisterCID` and `RenewDNS` function in `certifier.Certifier` with an `ACME` function that can be used instead. To call `RegisterCID`, simply call `certifier.ACME().RegisterCID()` - same with `RenewDNS`, simply call `certifier.ACME().RenewDNS()`

## [v0.3.1] - 2022-07-05

### Changes

- References to DNS-specific challenge providers are now more specific, and this should make it easier
  to support challenge types like the TLS-ALPN-01 challenge and the HTTP-01 challenge in the future
- Some extra logging has been added to make debugging errors easier

## [v0.3.0] - 2022-06-30

### Changes

- `pkg/storage` now requires errors to be returned in certain scenarios
- `internal/memory` implements the updated `storage` package interface and returns the proper errors

## [v0.2.0] - 2022-04-20

### Changes

- Refactoring the renewer package into `pkg/acme` package
- Refactoring certifier's DNS server into its own `pkg/dns` package
- Adding test cases for the `pkg/dns` package
- Adding comments and explanations (godoc style) for everything in Certifier
- moving `utils` package into the `pkg` directory
- moving the `memory` implementation of `storage.Storage` into the `internal` directory
- moving the `options` struct into its own `pkg/options` package

## [v0.1.0] - 2022-04-14

Initial Release of Certifier

[unreleased]: https://github.com/loopholelabs/certifier/compare/v0.3.2...HEAD
[v0.3.2]: https://github.com/loopholelabs/certifier/releases/tag/v0.3.2
[v0.3.1]: https://github.com/loopholelabs/certifier/releases/tag/v0.3.1
[v0.3.0]: https://github.com/loopholelabs/certifier/releases/tag/v0.3.0
[v0.2.0]: https://github.com/loopholelabs/certifier/releases/tag/v0.2.0
[v0.1.0]: https://github.com/loopholelabs/certifier/releases/tag/v0.1.0
