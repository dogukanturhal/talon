# Security policy

Talon sits in front of other applications and decides who may reach them, so
bugs here can expose everything behind it. Please report vulnerabilities
privately.

## Reporting a vulnerability

Use GitHub private vulnerability reporting: open the repository's **Security**
tab and choose **Report a vulnerability**
(<https://github.com/dogukanturhal/talon/security/advisories/new>).

If you cannot use GitHub, email **dogukanturhal@hexxlock.com**. Do not post
details in a public issue, discussion or chat.

Please include:

- What the issue is and which Talon version or image tag is affected.
- A way to reproduce it: configuration (TalonRoute or environment variables),
  the identity provider in use, what you saw and what you expected.
- Who can trigger it and what they gain.
- Whether you want to be credited.

We acknowledge reports within two business days.

## Disclosure

We follow a 90-day coordinated disclosure window from acknowledgement.

| Day | What happens |
|---|---|
| 0 | Report acknowledged, triage starts. |
| 0-7 | Severity assessed (CVSS v3.1); a CVE is requested if it applies. |
| 7-60 | Fix developed and reviewed privately. |
| ~90 | Patched release and advisory published together. |

A simple fix ships sooner. If the issue is being exploited we release
immediately. Reporters are credited unless they ask not to be. There is no bug
bounty.

## Supported versions

Talon is pre-1.0. Only the latest release receives security fixes.

## Scope

In scope: the `talon`, `talonctl`, `posture-signer`, `svctoken-refresher`,
`access-broker` and `audit-replay` binaries, the container image, the Helm
charts, the TalonRoute API and admission logic, and release artifacts
(checksums, SBOM, signatures).

Out of scope: vulnerabilities in the identity provider, SpiceDB, Redis,
Kubernetes or other dependencies (report those upstream; tell us if Talon's use
of them makes it worse), the `examples/quickstart` demo credentials (they are
public on purpose), and findings that require cluster-admin access.

## Verifying releases

Release assets carry a checksum file signed with cosign keyless signing, and an
SBOM. Container images are signed and have a build provenance attestation.

Dependencies are watched by Dependabot and CodeQL, and `govulncheck` runs on
every pull request.
