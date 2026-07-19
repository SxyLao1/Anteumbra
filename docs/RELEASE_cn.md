# 发布流程

[English](RELEASE.md)

Anteumbra 不会在每次推送 `main` 时自动发布 PyPI。GitHub 工作流
`.github/workflows/publish.yml` 只在推送版本 Tag 或手动触发时发布。

## 版本规则

项目采用 `里程碑.功能.bug修复`：低风险清理、可靠性改进和纯 Bug 修复只增加最后一位。

唯一版本来源：

```text
src/anteumbra/__init__.py
```

## PyPI 发布

PyPI 跟随最新已发布 Tag，而不是 GitHub `main` 的最新提交。打 Tag 前必须构建 Wheel，
并在全新虚拟环境安装该产物；可编辑源码安装不能替代分发产物测试。

```powershell
$cleanPaths = @("build", "dist", "src/anteumbra.egg-info")
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

本地发布必须执行清理与 Wheel/源码一致性检查。否则 Setuptools 可能保留旧
`build/lib` 中已删除的模块，并悄悄把它们重新装入新 Wheel。

确认生成的 `.env` 包含非占位 Session Secret；基础安装可使用 YARA；禁用的通知通道不会
访问外网；启动就绪失败时命令返回非零。

完成发布前质量门：

```powershell
cd F:\Home\Github\Anteumbra
python -m ruff check src tests
python -m pytest -q -rs --ignore=tests\e2e_ui
python -m pytest tests\e2e_ui -q
git diff --check
git status --short
git push origin main
git tag vX.Y.Z
git push origin vX.Y.Z
```

打 Tag 前还必须重建并运行 Docker 镜像，等待 `/api/v1/health` 返回 HTTP `200`，从宿主机
映射端口登录后台，并用一个无害检测样本走通 Registry、隔离和还原。宿主机登录用于验证
Docker 网关发现结果与后台 IP 白名单一致。源码测试通过不能替代 Wheel 或容器验证。

等待 `.github/workflows/publish.yml` 完成，再核对 GitHub 工作流与
`pip index versions anteumbra` 都显示新版本。PyPI 上传失败后不得复用同一版本号；修复
工作流并增加 bug 修复位。

PyPI 项目需要配置 GitHub Trusted Publishing：

```text
Owner: SxyLao1
Repository: Anteumbra
Workflow: publish.yml
Environment: pypi
```

如果 PyPI 未配置 Trusted Publishing，工作流会成功构建，但会在发布步骤失败。
