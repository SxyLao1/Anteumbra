# Release Process

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
python -m build --wheel
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

Confirm that the generated `.env` has a non-placeholder session secret, YARA
is available in the base install, no disabled notification channel attempts an
outbound connection, and startup exits non-zero when readiness fails.

Then publish a version:

```powershell
cd F:\Home\Github\Anteumbra
python -m pytest -q -rs --ignore=tests\e2e_ui
python -m pytest tests\e2e_ui -q
git status --short
git push origin main
git tag vX.Y.Z
git push origin vX.Y.Z
```

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
