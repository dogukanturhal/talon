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

## Keep pull requests small

This project has one maintainer who reads every line before merging. Large pull requests can't be reviewed properly, so they are not accepted.

- **One change per pull request.** One bug fix, one feature, or one refactor. Don't mix formatting or unrelated clean-ups into it.
- **Size limit: 400 changed lines and 15 files** (additions plus deletions; `go.sum`, `package-lock.json`, `Cargo.lock` and generated files don't count). Aim for under 200. An automated check fails pull requests over the limit.
- **Bigger change? Open an issue first.** Describe the plan and we'll agree on how to split it into a series of small pull requests that each build and pass tests on their own.
- Exceptions (for example, a large test fixture) only with a maintainer's agreement in the issue.

## AI-assisted contributions

You may use AI tools, under these conditions:

- **Say so** in the pull request description, and name what the tool did (for example "tests drafted with an AI assistant, then reviewed and edited").
- **You are the author.** You must understand every line and be able to explain and change it during review. "The tool wrote it" is not an answer to a review question.
- **Same rules as everyone:** the size limit above, tests, and the licence/sign-off requirements. You confirm you have the right to submit the code.
- Pull requests that look generated without review (code that doesn't fit the codebase, invented APIs, a PR description that doesn't match the diff, or no answers to review questions) are closed without detailed review.

## How your contribution lands

This GitHub repository is a mirror of our main development repository. When a pull request is merged here, we import it there with your authorship and sign-off preserved, and it comes back in the next sync. You don't need to do anything extra.

## Licensing of contributions

Contributions are licensed under AGPL-3.0-or-later. New Go files should start
with `// SPDX-License-Identifier: AGPL-3.0-or-later`.

## Conduct

Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).
