# Cosign — image signing for talon

Public key (`cosign.pub`) is committed to the repo so anyone can verify
signed images. The private key + password are GitLab CI variables on
`hexxlock/talon` (project ID 78), set as protected so they only inject into
pipelines on the default branch (`main`).

## CI variables

| Variable | Type | Masked | Protected | Purpose |
|----------|------|--------|-----------|---------|
| `COSIGN_PRIVATE_KEY` | file | n/a (file vars cannot be masked) | yes | Path to the encrypted ECDSA-P256 private key. Mounted into the runner only on `main` branch jobs. |
| `COSIGN_PASSWORD` | env_var | yes | yes | Decryption password for the private key. |

Both were generated 2026-04-26 with:

```
cosign generate-key-pair
```

The keypair is **per-project** (sibling falcon-id project has a distinct
keypair) so a compromise of one keypair does not invalidate signatures
on the other product line.

## Verify a Talon image manually

```
cosign verify --key deploy/cosign/cosign.pub \
  --insecure-ignore-tlog \
  --allow-insecure-registry \
  registry.example.com/talon/talon:<sha>
```

The CI `verify:talon` job runs the same command after build/sign/scan and
gates `bump-manifest` on success.

## Rotation

1. Generate a new keypair: `cosign generate-key-pair` in a tmp dir.
2. Upload the new `cosign.key` as `COSIGN_PRIVATE_KEY` (overwrite the
   existing CI File variable).
3. Update `COSIGN_PASSWORD` with the new password.
4. Replace `deploy/cosign/cosign.pub` in this directory and commit.
5. Mirror to `SECRETS.local.txt` per internal engineering notes.
6. The next `main` push signs with the new key; old signatures remain
   verifiable with the old `cosign.pub` if it is preserved in git history.
