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
To publish a new version:

```powershell
cd F:\Home\Github\Anteumbra
python -m pytest tests\core tests\tools tests\architecture tests\compatibility tests\e2e -q
python -m pytest tests\e2e_ui -q
git status --short
git tag v1.0.22
git push origin main
git push origin v1.0.22
```

The PyPI project must also have GitHub Trusted Publishing configured for:

```text
Owner: SxyLao1
Repository: Anteumbra
Workflow: publish.yml
Environment: pypi
```

If Trusted Publishing is not configured on PyPI, the workflow will build the
package but fail at the publish step.
