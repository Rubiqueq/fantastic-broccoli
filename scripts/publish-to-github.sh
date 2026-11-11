#!/usr/bin/env bash
set -euo pipefail
# Run from an authenticated workstation, NOT from an unauthenticated GitHub App.
# Requires: gh auth login, repository push permission, and GitHub Actions enabled.
REPO="${1:-Rubiqueq/fantastic-broccoli}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
command -v gh >/dev/null || { echo 'GitHub CLI gh is required' >&2; exit 1; }
command -v git >/dev/null || { echo 'git is required' >&2; exit 1; }
gh auth status >/dev/null
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
gh repo clone "$REPO" "$TMP/remote"
cd "$TMP/remote"
if [ "$(git branch --show-current)" != main ]; then
  echo 'Expected main branch. Refusing to push onto unknown branch.' >&2
  exit 1
fi
mkdir -p app/src/main/java/com/rubiqueq/saf server/scheduler scripts docs .github/workflows
cp "$SRC/app/src/main/java/com/rubiqueq/saf/"*.java app/src/main/java/com/rubiqueq/saf/
cp "$SRC/app/src/main/AndroidManifest.xml" app/src/main/AndroidManifest.xml
cp "$SRC/app/build.gradle.kts" app/build.gradle.kts
cp "$SRC/server/main.go" "$SRC/server/queue_adapter.go" "$SRC/server/queue_adapter_test.go" "$SRC/server/go.mod" server/
cp "$SRC/server/scheduler/"*.go server/scheduler/
cp "$SRC/scripts/fetch_rubingo_source.sh" "$SRC/scripts/publish-to-github.sh" scripts/
cp "$SRC/Dockerfile" "$SRC/README_FA.md" "$SRC/settings.gradle.kts" "$SRC/build.gradle.kts" "$SRC/gradle.properties" .
# Disable obsolete build definitions so push never republishes any prior APK.
rm -f .github/workflows/rubika-saf-build.yml .github/workflows/build-internet-source.yml
cp "$SRC/.github/workflows/build-queue.yml" .github/workflows/build-queue.yml
cp "$SRC/docs/TEST-MATRIX.md" docs/TEST-MATRIX.md
# Existing checked-in MIT library and its LICENSE remain untouched in remote.
git add app server scripts Dockerfile README_FA.md settings.gradle.kts build.gradle.kts gradle.properties docs/TEST-MATRIX.md
# Include removals of obsolete workflows in the exact same commit.
git add -A .github/workflows
if git diff --cached --quiet; then
  echo 'No changes to publish.'
  exit 0
fi
git diff --cached --stat
git commit -m 'feat: Rubika SAF RC2 durable Excel/CSV queue, scheduled sending, media safety'
git push origin HEAD:main
printf 'New source pushed. Check actions: https://github.com/%s/actions\n' "$REPO"
