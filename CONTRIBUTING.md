# Contributing to Talon

Thanks for helping. Talon is an AGPL-3.0-or-later identity-aware proxy written
in Go.

## Before you start

- Skim the design records in [docs/architecture](docs/architecture). They
  explain choices that are not obvious from the code (cookie and session
  format, fail-mode policy, the TalonRoute CRD).
- For a new TalonRoute field, a change to the session or token formats, or
  anything that changes what a request is allowed to do, open an issue first
  and describe the design. Small fixes, tests and docs can go straight to a
  pull request.
- Security issues do not belong in issues: see [SECURITY.md](SECURITY.md).

## Sign off your commits (DCO)

Every commit needs a `Signed-off-by` line, which certifies the
[Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s -m "router: deny when the posture header is malformed"
```

To fix a missing sign-off: `git commit --amend -s` or
`git rebase --signoff main`.

## Development setup

You need the Go version in `go.mod`. Redis and SpiceDB are only needed for
manual testing; unit tests do not start them.

```sh
go build ./...
go vet ./...
go test -race ./...
golangci-lint run        # uses .golangci.yml
```

To try changes end to end, use [examples/quickstart](examples/quickstart):
`docker compose up --build` rebuilds the image from your working tree.

## Pull requests

- Branch from `main`; keep the change focused.
- Commit messages: short imperative subject (`area: what changed`), body
  explains why.
- Add or update tests. A fix should come with a test that fails without it.
- Update `CHANGELOG.md` under `[Unreleased]` for anything user-visible.
- Say what you ran. If you changed authentication or authorization behaviour,
  say which identity provider you tested against.

## Licensing of contributions

Contributions are licensed under AGPL-3.0-or-later. New Go files should start
with `// SPDX-License-Identifier: AGPL-3.0-or-later`.

## Conduct

Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).
