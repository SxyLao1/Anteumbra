# Release Process

[中文](RELEASE_cn.md)

Anteumbra does not publish to PyPI from every `main` push. The GitHub workflow
`.github/workflows/publish.yml` publishes only when a version tag is pushed or
when the workflow is triggered manually.

## Versioning

The project uses `milestone.feature.bugfix` versioning. Low-risk cleanup and
bugfix-only work should increment only the bugfix number.

The single source of truth is:

```text
src/anteumbra/__init__.py
```

## PyPI Publishing

PyPI currently follows the latest published tag, not the latest GitHub commit.
Before tagging, build the wheel and install that artifact into a new virtual
environment. An editable source install is not a distribution test.

```powershell
$cleanPaths = @("build\lib", "dist", "src/anteumbra.egg-info")
Remove-Item -Recurse -Force $cleanPaths -ErrorAction SilentlyContinue
python -m build --wheel
python scripts/verify_wheel_contents.py dist
python -m venv .release-smoke
.\.release-smoke\Scripts\python -m pip install dist\anteumbra-X.Y.Z-py3-none-any.whl
.\.release-smoke\Scripts\anteumbra install .release-instance
$env:ANTEUMBRA_HOME = (Resolve-Path .release-instance)
.\.release-smoke\Scripts\anteumbra config validate
.\.release-smoke\Scripts\anteumbra start
.\.release-smoke\Scripts\anteumbra status
Invoke-RestMethod http://127.0.0.1:8080/api/v1/health
.\.release-smoke\Scripts\anteumbra stop
Remove-Item Env:ANTEUMBRA_HOME
```

The cleanup and Wheel/source parity check are mandatory for local releases.
Setuptools can otherwise retain deleted modules from an old `build/lib`
directory and silently place them back into a new Wheel.

Confirm that the generated `.env` has a non-placeholder session secret, YARA
is available in the base install, no disabled notification channel attempts an
outbound connection, and startup exits non-zero when readiness fails.

Then promote the validated development branch and publish a version:

```powershell
cd F:\Home\Github\Anteumbra
python -m ruff check src tests
python -m pytest -q -rs --ignore=tests\e2e_ui
python -m pytest tests\e2e_ui -q
git diff --check
git status --short
git switch dev
git push origin dev
```

Open a `dev -> main` promotion pull request. Wait for every required check to
pass, merge the promotion PR, and verify that any `Closes #N` or `Fixes #N`
references in its body closed their issues. Use `N/A` when no issue applies.
The repository must keep automatic head-branch deletion enabled.

After the promotion merge:

```powershell
git switch main
git pull --ff-only origin main
git tag vX.Y.Z
git push origin vX.Y.Z
```

Before the tag, also rebuild and run the Docker image, wait for
`/api/v1/health` to return HTTP `200`, log in through the published host port,
and exercise one harmless detection file through Registry and
quarantine/restore. The host login verifies that Docker gateway discovery and
the admin IP allowlist agree. A passing source test suite does not replace
wheel or container validation.

Wait for `.github/workflows/publish.yml`, then verify both the GitHub release
workflow and `pip index versions anteumbra` report the tagged version. Do not
reuse a version number after a failed PyPI upload; fix the workflow and bump the
bugfix component.

The PyPI project must also have GitHub Trusted Publishing configured for:

```text
Owner: SxyLao1
Repository: Anteumbra
Workflow: publish.yml
Environment: pypi
```

If Trusted Publishing is not configured on PyPI, the workflow will build the
package but fail at the publish step.


## Docker Runtime Backup and Restore

The named volume mounted at `/var/lib/anteumbra` contains the runtime configuration,
credentials and TOTP state, rules, records, quarantine history, logs and bundled
site files. Back up external website mounts separately. This procedure runs from
a source checkout in a POSIX shell and uses the included snapshot helper.

Build the candidate locally and set both image references to your exact tags or
immutable digests. The example does not imply that either image is published.
Stop all writers before taking the snapshot. The helper refuses existing snapshot
names and nonempty restore destinations, validates the archive SHA-256, and
compares every restored file, permission and numeric owner, including the runtime
root directory. Links and special files are rejected. Keep the archive and both
sidecars together and private: the archive contains credentials and site data.
Use snapshots from a trusted backup location; the sidecar detects corruption,
not who created the archive. Archive contents and metadata are checked before
extraction and again after restore. If a backup or restore fails, retain the
failed output for diagnosis and retry with a new snapshot name or a new empty
volume. Never use a partially restored volume as a runtime.

```bash
set -eu
OLD_IMAGE='anteumbra:1.0.47'
NEW_IMAGE='anteumbra:1.0.48'
RUNTIME_VOLUME='anteumbra-runtime'
RESTORE_VOLUME='anteumbra-runtime-restored'
SNAPSHOT='before-upgrade.tar.gz'
SCRIPT="$(pwd)/scripts/docker_runtime_snapshot.py"
BACKUPS="$(pwd)/anteumbra-runtime-snapshots"

test -f "$SCRIPT"
test "$(docker inspect -f '{{.Config.Image}}' anteumbra)" = "$OLD_IMAGE"
test "$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/var/lib/anteumbra"}}{{.Name}}{{end}}{{end}}' anteumbra)" = "$RUNTIME_VOLUME"
docker volume inspect "$RUNTIME_VOLUME" >/dev/null
# The old 1.0.47 runtime handles SIGINT; 1.0.48 also handles Docker's SIGTERM.
docker stop --signal SIGINT --timeout 30 anteumbra
test "$(docker inspect -f '{{.State.ExitCode}}' anteumbra)" = '0'
mkdir -p "$BACKUPS"
docker run --rm --network none --user 0 --entrypoint python \
  -v "$RUNTIME_VOLUME:/runtime:ro" -v "$BACKUPS:/backup" \
  -v "$SCRIPT:/snapshot.py:ro" "$NEW_IMAGE" /snapshot.py backup \
  --archive "/backup/$SNAPSHOT"

if docker volume inspect "$RESTORE_VOLUME" >/dev/null 2>&1; then
  echo "Restore volume already exists; choose a new name." >&2
  exit 1
fi
docker volume create "$RESTORE_VOLUME"
docker run --rm --network none --user 0 --entrypoint python \
  -v "$RESTORE_VOLUME:/runtime" -v "$BACKUPS:/backup:ro" \
  -v "$SCRIPT:/snapshot.py:ro" "$NEW_IMAGE" /snapshot.py restore \
  --archive "/backup/$SNAPSHOT"

docker run -d --name anteumbra-upgrade \
  -p 127.0.0.1:18080:8080 \
  -e ANTEUMBRA_HOME=/var/lib/anteumbra \
  -v "$RESTORE_VOLUME:/var/lib/anteumbra" "$NEW_IMAGE"
```

Log in to the replacement with the existing credentials and TOTP, check site
configuration, custom rules and quarantine history, then complete one harmless
detection and quarantine/restore operation. A healthy endpoint alone does not
prove recovery. Keep the original stopped container, original volume and snapshot
until the replacement has been accepted.

In this procedure the new image writes only to the restored volume. To roll back,
stop it and start the original container with its untouched pre-upgrade volume:

```bash
docker stop --timeout 30 anteumbra-upgrade
test "$(docker inspect -f '{{.State.ExitCode}}' anteumbra-upgrade)" = '0'
docker start anteumbra
```

If a new version has already written to the original volume, do not attach the
old image to it. Restore the pre-upgrade snapshot into another new volume with
the same helper, then start the old image against that restored volume. Preserve
the newer volume for investigation. These steps do not remove existing volumes.
