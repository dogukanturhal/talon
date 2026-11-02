# Changelog

All notable changes to Talon are documented here. The project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Docker Compose quickstart in `examples/quickstart`: Talon with SpiceDB,
  Redis, a mock OIDC provider and a demo upstream, showing an allowed and a
  denied user.
- GitHub Actions for CI (vet, race-enabled tests, golangci-lint, govulncheck,
  image build), CodeQL, OpenSSF Scorecard and tag-driven releases with
  GoReleaser, keyless cosign signatures and SBOMs.
- Issue templates, Dependabot configuration, `SECURITY.md`, `CONTRIBUTING.md`
  (DCO sign-off) and a Code of Conduct.

### Changed

- First public sync from the development repository. Documentation and
  manifests were cleaned for public use: placeholder hostnames and registries
  replaced, internal operations runbooks and environment-specific test suites
  withheld.
- The container image is built with a plain public `Dockerfile` (no private
  module proxy, multi-architecture ready) and is labelled AGPL-3.0-or-later.
- The README was rewritten.
