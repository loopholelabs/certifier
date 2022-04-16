# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[unreleased]: https://github.com/loopholelabs/certifier/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/loopholelabs/certifier/releases/tag/v0.1.0
