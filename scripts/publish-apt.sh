#!/usr/bin/env bash
# publish-apt.sh — publish talonctl .debs to the HexxLock APT channel at
# internal.example.com, so developers install and upgrade with plain apt.
#
# WHY APT AND NOT A GITLAB RELEASE
# ================================
# Every other channel for this particular binary is circular. talonctl is
# the tool that mints Talon tokens, so it cannot be fetched from anything
# Talon fronts: not npm.ops (it authenticates you TO that registry), not
# harbor.ops, and not gitlab.ops — `curl` there gets a 401 before GitLab
# ever sees the request.
#
# internal.example.com is the one distribution surface that is NOT
# IAP-gated (it is a Traefik route straight to MinIO, no Talon
# middleware), so apt can reach it with no credential at all. That
# dissolves the bootstrap problem rather than working around it, and it
# means upgrades are `apt upgrade` instead of a hand-rolled
# self-download.
#
# Verification comes free and is not optional: apt refuses a repo whose
# InRelease signature does not verify against the installed keyring. That
# is strictly better than shipping a detached signature next to a binary
# and hoping people run the verify command.
#
# ⚠ SEPARATE SUITE, ON PURPOSE
# ============================
# hexxlock-access publishes to dists/stable/ from its own tag-only job
# (hexxlock-access/scripts/publish-release.sh). apt-ftparchive REGENERATES
# a suite's Release file from scratch, listing only the components it was
# told about — so if both products regenerated dists/stable/, whichever
# ran second would silently drop the other's component and break installs
# for it.
#
# talonctl therefore owns dists/tools/ and pool/tools/ exclusively.
# Nothing in this script touches dists/stable/ or pool/main/. The two
# publishers share the bucket, the CDN host and the GPG key, and share no
# mutable metadata.
#
# ⚠ KNOWN DUPLICATION
# ===================
# The GPG/apt-ftparchive logic here overlaps hexxlock-access's
# publish-release.sh. That is deliberate for now and should not persist:
# extending that script was not available because it lives in a different
# repo and is Tauri-coupled (Ed25519 updater signatures, latest.json)
# which talonctl has no use for. The convergence target is a shared
# shared-ci-templates template both repos include. Until then, a change to the
# signing or Release-composition logic must be made in BOTH places.
set -euo pipefail

: "${VAULT_ADDR:?VAULT_ADDR required}"
: "${VAULT_TOKEN:?VAULT_TOKEN required — obtain via the JWT login in CI}"
: "${PKG_VERSION:?PKG_VERSION required (must sort monotonically; see CI)}"

SUITE="${SUITE:-tools}"
COMPONENT="${COMPONENT:-main}"
POOL="${POOL:-pool/tools}"
MINIO_ALIAS="${MINIO_ALIAS:-hexxops}"
MINIO_BUCKET="${MINIO_BUCKET:-hexxlock-access-updates}"
ARCHES="${ARCHES:-amd64 arm64}"
DIST_DIR="${DIST_DIR:-dist}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
APT="$WORK/apt"
mkdir -p "$APT/$POOL"

for a in $ARCHES; do
  mkdir -p "$APT/dists/$SUITE/$COMPONENT/binary-$a"
done

# ── 1. Secrets ─────────────────────────────────────────────────────────
# These live under .../platform/cdn-ops/ — named for the surface they
# belong to, not the product that created them. Both the APT signing
# identity and the CDN bucket are shared by every tool published to
# internal.example.com, so a product-scoped path (they were previously
# under .../hexxlock-access/) made every additional publisher look like it
# was borrowing another team's secrets.
echo "==> reading signing material from Vault"
gpg_priv=$(curl -fsS -H "X-Vault-Token: $VAULT_TOKEN" \
  "$VAULT_ADDR/v1/example/data/platform/cdn-ops/gpg-signing" | jq -r '.data.data.private')
gpg_fp=$(curl -fsS -H "X-Vault-Token: $VAULT_TOKEN" \
  "$VAULT_ADDR/v1/example/data/platform/cdn-ops/gpg-signing" | jq -r '.data.data.fingerprint')
mc_json=$(curl -fsS -H "X-Vault-Token: $VAULT_TOKEN" \
  "$VAULT_ADDR/v1/example/data/platform/cdn-ops/minio")
mc_url=$(jq -r '.data.data.url' <<<"$mc_json")
mc_ak=$(jq -r '.data.data.access_key' <<<"$mc_json")
mc_sk=$(jq -r '.data.data.secret_key' <<<"$mc_json")

export GNUPGHOME="$WORK/gnupg"
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
printf '%s' "$gpg_priv" | base64 -d 2>/dev/null | gpg --batch --quiet --import 2>/dev/null \
  || printf '%s' "$gpg_priv" | gpg --batch --quiet --import

# ── 2. Stage the .debs ─────────────────────────────────────────────────
# Only OUR pool path is populated. apt-ftparchive is pointed at it
# explicitly below so it can never index another product's packages into
# this suite.
echo "==> staging .debs into $POOL/"
for a in $ARCHES; do
  deb="$DIST_DIR/talonctl_${PKG_VERSION}_${a}.deb"
  [ -s "$deb" ] || { echo "error: missing $deb" >&2; exit 1; }
  cp "$deb" "$APT/$POOL/"
done

# ── 3. Pull the CURRENT pool down before regenerating ──────────────────
# apt-ftparchive builds Packages from whatever is on disk, so publishing
# only the new .deb would delist every previous version — `apt install
# talonctl=<older>` and any pinned rollback would 404. Sync the existing
# pool first so the index describes the whole channel, not just this run.
echo "==> configuring mc + syncing existing pool"
mc alias set "$MINIO_ALIAS" "$mc_url" "$mc_ak" "$mc_sk" >/dev/null
mc cp --quiet --recursive "$MINIO_ALIAS/$MINIO_BUCKET/apt/$POOL/" "$APT/$POOL/" 2>/dev/null || \
  echo "    (no existing pool — first publish)"

# ── 4. Indices, per architecture ───────────────────────────────────────
cd "$APT"
for a in $ARCHES; do
  echo "==> Packages for $a"
  apt-ftparchive -o Dir::Pool="$APT" \
                 -o APT::FTPArchive::AlwaysStat=true \
                 --arch "$a" packages "$POOL" \
                 > "dists/$SUITE/$COMPONENT/binary-$a/Packages"
  gzip -9c "dists/$SUITE/$COMPONENT/binary-$a/Packages" \
        > "dists/$SUITE/$COMPONENT/binary-$a/Packages.gz"
done

echo "==> composing Release"
cat > "$APT/aptftp.conf" <<EOF
APT::FTPArchive::Release {
  Origin "HexxLock Platform";
  Label "HexxLock Developer Tools";
  Suite "$SUITE";
  Codename "$SUITE";
  Architectures "$ARCHES";
  Components "$COMPONENT";
  Description "HexxLock developer CLI tools — APT channel";
  Date "$(date -Ru)";
};
EOF
apt-ftparchive -c "$APT/aptftp.conf" release "dists/$SUITE/" > "dists/$SUITE/Release"

# Both signature forms: InRelease is the modern inline-signed file apt
# prefers; Release.gpg is the detached form older clients still fetch.
# Shipping only one silently breaks whichever half of the fleet uses the
# other.
echo "==> signing Release"
gpg --batch --yes --pinentry-mode loopback -u "$gpg_fp" --clearsign \
    -o "dists/$SUITE/InRelease" "dists/$SUITE/Release"
gpg --batch --yes --pinentry-mode loopback -u "$gpg_fp" --detach-sign --armor \
    -o "dists/$SUITE/Release.gpg" "dists/$SUITE/Release"

# Public keyring, so the install one-liner has something to fetch. Written
# every run because it is derived from the same key that just signed —
# a rotated key would otherwise leave clients unable to verify.
gpg --batch --yes --export "$gpg_fp" > "$APT/hexxlock.gpg"

# ── 5. Upload ──────────────────────────────────────────────────────────
# Pool first, indices last. apt reads Release -> Packages -> .deb, so
# publishing an index that references a .deb not yet uploaded would make
# the channel briefly broken for anyone running apt update in that window.
echo "==> uploading to $MINIO_ALIAS/$MINIO_BUCKET/apt/"
mc cp --quiet --recursive "$APT/$POOL/" "$MINIO_ALIAS/$MINIO_BUCKET/apt/$POOL/"
for a in $ARCHES; do
  mc cp --quiet "dists/$SUITE/$COMPONENT/binary-$a/Packages" \
    "$MINIO_ALIAS/$MINIO_BUCKET/apt/dists/$SUITE/$COMPONENT/binary-$a/Packages"
  mc cp --quiet "dists/$SUITE/$COMPONENT/binary-$a/Packages.gz" \
    "$MINIO_ALIAS/$MINIO_BUCKET/apt/dists/$SUITE/$COMPONENT/binary-$a/Packages.gz"
done
mc cp --quiet "dists/$SUITE/Release"     "$MINIO_ALIAS/$MINIO_BUCKET/apt/dists/$SUITE/Release"
mc cp --quiet "dists/$SUITE/InRelease"   "$MINIO_ALIAS/$MINIO_BUCKET/apt/dists/$SUITE/InRelease"
mc cp --quiet "dists/$SUITE/Release.gpg" "$MINIO_ALIAS/$MINIO_BUCKET/apt/dists/$SUITE/Release.gpg"
mc cp --quiet "$APT/hexxlock.gpg"        "$MINIO_ALIAS/$MINIO_BUCKET/apt/hexxlock.gpg"

# macOS is not an apt platform. The darwin binary is published as a plain
# file beside the repo with its checksum, which is the honest fallback
# rather than pretending apt covers it.
if [ -s "$DIST_DIR/talonctl_darwin_arm64" ]; then
  echo "==> uploading darwin/arm64 (non-apt fallback)"
  mc cp --quiet "$DIST_DIR/talonctl_darwin_arm64" \
    "$MINIO_ALIAS/$MINIO_BUCKET/apt/darwin/talonctl_${PKG_VERSION}_darwin_arm64"
  mc cp --quiet "$DIST_DIR/talonctl_darwin_arm64" \
    "$MINIO_ALIAS/$MINIO_BUCKET/apt/darwin/talonctl_darwin_arm64"
  [ -s "$DIST_DIR/SHA256SUMS" ] && mc cp --quiet "$DIST_DIR/SHA256SUMS" \
    "$MINIO_ALIAS/$MINIO_BUCKET/apt/darwin/SHA256SUMS"
fi

echo "INFO: published talonctl ${PKG_VERSION} to ${SUITE}/${COMPONENT} (${ARCHES})"
