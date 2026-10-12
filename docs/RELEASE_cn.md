# 发布流程

[English](RELEASE.md)

Anteumbra 不会在每次推送 `main` 时自动发布 PyPI。GitHub 工作流
`.github/workflows/publish.yml` 只在推送版本 Tag 或以版本 Tag 作为工作流引用手动触发时发布。
工作流会检查 Tag 版本与包版本一致。

## 版本规则

项目采用 `里程碑.功能.bug修复`：低风险清理、可靠性改进和纯 Bug 修复只增加最后一位。

唯一版本来源：

```text
src/anteumbra/__init__.py
```

## PyPI 发布

只有针对准确发布 Tag 成功完成 `publish.yml`，才能证明 PyPI 发布完成。
发布前必须分别核对 PyPI 与对应 GitHub Tag。
不能根据 GitHub 提交推断 PyPI 已发布，也不能为修复历史发布记录而重建或移动历史 Tag。
打 Tag 前必须构建 Wheel，并在全新虚拟环境安装该产物；可编辑源码安装不能替代分发产物测试。

```powershell
$releaseCheckout = Join-Path $env:TEMP "anteumbra-release-checkout"
if (Test-Path -LiteralPath $releaseCheckout) {
    throw "请选择新的空发布检出目录：$releaseCheckout"
}
git clone --branch <validated-branch> https://github.com/SxyLao1/Anteumbra.git $releaseCheckout
Set-Location -LiteralPath $releaseCheckout
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

完成发布前质量门后，按两个受保护 Pull Request 推进已验证的功能分支。
每个 Pull Request 都必须通过六项必需检查：Python 3.10、Python 3.11、Python 3.12、
Playwright UI、Build Check 和 Docker Build。

```powershell
python -m ruff check src tests
python -m pytest -q -rs --ignore=tests\e2e_ui
python -m pytest tests\e2e_ui -q
git diff --check
git status --short
git push origin <validated-feature-branch>
```

创建 `<validated-feature-branch> -> dev` Pull Request，等待六项必需检查全部通过后合并。
再创建 `dev -> main` promotion Pull Request，等待晋级提交上的六项必需检查全部通过后合并。
仓库必须保持自动删除已合并源分支的设置。

promotion 合并后：

```powershell
git switch main
git pull --ff-only origin main
git tag vX.Y.Z
git push origin vX.Y.Z
```

打 Tag 前还必须重建并运行 Docker 镜像，等待 `/api/v1/health` 返回 HTTP `200`，从宿主机
映射端口登录后台，并用一个无害检测样本走通 Registry、隔离和还原。宿主机登录用于验证
Docker 网关发现结果与后台 IP 白名单一致。源码测试通过不能替代 Wheel 或容器验证。

等待 `.github/workflows/publish.yml` 完成，再分别核对 PyPI 与 GitHub Tag 都显示准确版本。
`publish.yml` 只向 PyPI 发布，不会创建 GitHub Release。应从已核对的 Tag 单独创建 GitHub Release。
PyPI 上传失败后不得复用同一版本号；修复工作流并增加 bug 修复位。

PyPI 项目需要配置 GitHub Trusted Publishing：

```text
Owner: SxyLao1
Repository: Anteumbra
Workflow: publish.yml
Environment: pypi
```

如果 PyPI 未配置 Trusted Publishing，工作流会成功构建，但会在发布步骤失败。


## Docker 运行目录备份与恢复

挂载到 `/var/lib/anteumbra` 的命名卷包含运行配置、凭据与 TOTP 状态、规则、检测记录、隔离历史、日志和卷内站点文件。
卷外网站挂载需要单独备份。
以下步骤从源码仓库目录在 POSIX shell 中执行，使用仓库自带的快照工具。

先在本地构建候选镜像，再把两个镜像引用设置为确定的标签或不可变摘要。
示例不代表这些镜像已经公开发布。
备份前必须停止全部写入方。
工具拒绝覆盖已有快照或向非空目录恢复，先核对压缩包 SHA-256，再逐项核对恢复后的文件内容、权限和数字 UID/GID，包含运行根目录。
链接（包括符号链接和硬链接）及特殊文件会被拒绝。
压缩包及两个旁侧校验文件须一起保留并限制访问，因为压缩包含凭据和站点数据。
只使用可信备份位置中的快照；校验文件用于发现损坏，不能证明归档来源。
工具在解包前核对内容与元数据，恢复后再次对账。备份或恢复失败时保留失败产物用于排查，
改用新的快照名称或新的空卷重试，不能将部分恢复的卷直接作为运行实例。

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
# 旧版 1.0.47 用 SIGINT 正常退出；1.0.48 也支持 Docker 默认的 SIGTERM。
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

使用原有凭据及 TOTP 登录替换容器，回读站点配置、自定义规则和隔离历史，再完成一轮无害检测、隔离与还原。
健康接口正常不能单独证明恢复成功。
替换容器验收前，保留停止状态的原容器、原卷和完整快照。

本流程中新版只写恢复卷，原卷保持升级前状态。
回滚时停止新版，再启动连接原卷的旧容器：

```bash
docker stop --timeout 30 anteumbra-upgrade
test "$(docker inspect -f '{{.State.ExitCode}}' anteumbra-upgrade)" = '0'
docker start anteumbra
```

若新版已经写入原卷，不能直接把旧镜像接到该卷。
应使用同一工具把升级前快照恢复到另一个新卷，再用旧镜像启动该恢复卷，并保留新版卷供调查。
以上步骤不会删除已有数据卷。
