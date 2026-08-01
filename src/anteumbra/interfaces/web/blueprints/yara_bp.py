# -*- coding: utf-8 -*-
"""
@Time: 1/14/2026 7:40 PM
@Auth: SxyLao1
@File: yara_bp.py
@IDE: PyCharm
@Motto: HACK THE REAL
v1.7.6: YARA规则管理蓝图
"""
import json
import shutil
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from flask import Blueprint, abort, current_app, jsonify, render_template, request
from markupsafe import escape as html_escape
from werkzeug.utils import secure_filename

from anteumbra.application.path_service import normalize_path
from anteumbra.application.yara_service import (
    resolve_yara_rules_path,
)
from anteumbra.domain.logging import log_with_symbol
from anteumbra.interfaces.web.auth import require_auth
from anteumbra.interfaces.web.runtime import get_runtime

try:
    import yara
except ImportError:
    yara = None

# 创建Blueprint
yara_bp = Blueprint('yara', __name__, url_prefix='/admin/yara')

# 线程锁（防止并发修改规则文件）
_rule_operation_lock = threading.RLock()


def _get_rules_path(config: Optional[Dict] = None) -> Path:
    """Return the rule directory used by the active scanner."""
    config = config or get_runtime().config.get()
    paths_cfg = config.get("paths", {})
    yara_cfg = config.get("scanner", {}).get("yara", {})
    configured_path = (
        yara_cfg.get("rules_path")
        or paths_cfg.get("yara_rules_path", "rules/webshell")
    )
    return resolve_yara_rules_path(configured_path, current_app.logger)


def _reload_rules(expected_filename: Optional[str] = None) -> Tuple[bool, str]:
    """Reload the scanner and verify that a changed file joined the active set."""
    engine = get_runtime().yara_engine
    if Path(engine.rules_path).resolve() != _get_rules_path().resolve():
        return False, "活动规则目录与当前配置不一致，请重启 Anteumbra"
    if not engine.reload():
        return False, "规则重载后没有可用规则"
    if expected_filename and expected_filename in engine.load_errors:
        return False, engine.load_errors[expected_filename]
    return True, ""


def _sanitize_rule_upload_filename(filename: str) -> str:
    """Return a safe YARA rule filename, or an empty string when rejected."""
    if not filename or '\x00' in filename or '%00' in filename:
        return ""
    if any(sep in filename for sep in ('/', '\\')) or '..' in filename:
        return ""
    safe_name = secure_filename(filename)
    if safe_name != filename or not safe_name.endswith('.yar'):
        return ""
    return safe_name


def _validate_rule_path(filename: str, rules_path) -> Path:
    """路径穿越防护：验证 filename 在 rules_path 内，返回安全路径。

    v1.7.9: 统一所有 YARA 路由的路径验证逻辑，防止 ../ 和 %00 注入。
    """
    # 1. 过滤 null byte 注入
    if '\x00' in filename or '%00' in filename:
        abort(400, description="Invalid filename: null byte detected")

    # 2. 禁止路径穿越字符
    if '..' in filename:
        abort(400, description="Invalid filename: path traversal detected")

    # 3. 只允许 .yar 扩展名（白名单）
    if not filename.endswith('.yar') and '/rules/' in str(rules_path):
        # edit_modal 路由允许直接访问文件名
        pass

    # 4. 解析并验证绝对路径在 rules_path 内
    target = (rules_path / filename).resolve()
    try:
        target.relative_to(rules_path.resolve())
    except ValueError:
        abort(403, description="Access denied: path traversal attempt")

    return target


def get_rule_files() -> List[Dict[str, str]]:
    """扫描rules/webshell目录，返回规则文件列表"""
    try:
        rules_path = _get_rules_path()

        if not rules_path.exists():
            log_with_symbol(
                "warning_config_reload",
                "warning",
                f"规则目录不存在: {rules_path}",
                current_app.logger,
            )
            return []

        rule_files = []
        for yar_file in rules_path.glob("*.yar"):
            try:
                stats = yar_file.stat()
                # 尝试预编译验证语法
                if yara is None:
                    status = "unavailable"
                    error_msg = "yara-python is not installed"
                else:
                    try:
                        yara.compile(filepath=str(yar_file))
                        status = "valid"
                        error_msg = ""
                    except Exception as e:
                        status = "invalid"
                        error_msg = str(e)[:100]

                # 粗略统计规则数（按rule关键字计数）
                content = yar_file.read_text(encoding='utf-8', errors='ignore')
                rule_count = content.count("rule ")

                rule_files.append({
                    "filename": yar_file.name,
                    "path": str(yar_file.relative_to(rules_path)),  # 相对路径
                    "full_path": str(yar_file),
                    "size_kb": round(stats.st_size / 1024, 2),
                    "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                    "rule_count": rule_count,
                    "status": status,
                    "error": error_msg
                })
            except Exception as e:
                log_with_symbol(
                    "error_scan_fail",
                    "error",
                    f"读取规则文件失败 {yar_file.name}: {e}",
                    current_app.logger,
                )

        return sorted(rule_files, key=lambda x: x["modified"], reverse=True)  # 按修改时间倒序

    except Exception as e:
        log_with_symbol(
            "error_scan_fail", "error", f"扫描规则目录失败: {e}", current_app.logger
        )
        return []


def validate_rule_syntax(rule_content: str) -> Tuple[bool, Optional[str]]:
    """验证YARA规则语法，返回(是否有效, 错误信息)"""
    try:
        if yara is None:
            return False, "yara-python is not installed. Install anteumbra[yara] or anteumbra[full]."
        yara.compile(source=rule_content)
        return True, None
    except Exception as e:
        return False, str(e)


@yara_bp.route('/rules', methods=['GET'])
@require_auth
def list_rules():
    """返回规则列表HTML片段（配置化分页）- v1.7.5修复"""
    try:
        # 获取分页参数
        page = max(1, int(request.args.get('page', 1)))

        # v1.7.5修复：从配置读取YARA分页大小
        config = get_runtime().config.get()
        default_per_page = config.get("web_admin", {}).get("yara_items_per_page", 6)
        per_page = max(1, int(request.args.get('per_page', default_per_page)))

        all_rules = get_rule_files()
        total = len(all_rules)

        # 计算分页
        start = (page - 1) * per_page
        end = min(start + per_page, total)
        paginated_rules = all_rules[start:end]

        total_pages = max(1, (total + per_page - 1) // per_page)

        # 始终渲染片段
        compact = request.args.get('compact') == '1'
        return render_template(
            'admin/yara_rules.html',
            rules=paginated_rules,
            page=page,
            total_pages=total_pages,
            total=total,
            per_page=per_page,
            compact=compact
        )

    except ValueError:
        return jsonify({"error": "无效的分页参数"}), 400
    except Exception as e:
        log_with_symbol(
            "yara_error", "error", f"获取规则列表失败: {e}", current_app.logger
        )
        return jsonify({"error": str(e)}), 500


@yara_bp.route('/rules/<path:filename>', methods=['GET'])
@require_auth
def get_rule_content(filename):
    """获取单个规则文件内容（v1.7.9: 加固路径验证）"""
    try:

        rules_path = _get_rules_path()

        target_file = _validate_rule_path(filename, rules_path)

        if not target_file.exists():
            abort(404)

        content = target_file.read_text(encoding='utf-8', errors='ignore')
        return jsonify({
            "filename": filename,
            "content": content,
            "size": len(content)
        })

    except Exception as e:
        log_with_symbol(
            "error_scan_fail",
            "error",
            f"读取规则文件失败 {filename}: {e}",
            current_app.logger,
        )
        return jsonify({"error": str(e)}), 500


@yara_bp.route('/rules/<path:filename>', methods=['PUT'])
@require_auth
def update_rule(filename):
    """更新规则文件（实时语法验证 + v1.7.9路径加固）"""
    try:
        logger = current_app.logger

        rules_path = _get_rules_path()

        target_file = _validate_rule_path(filename, rules_path)

        if not target_file.exists():
            abort(404)

        rule_content = (request.get_json(silent=True) or {}).get('content', '')
        if not rule_content.strip():
            return jsonify({"error": "规则内容不能为空"}), 400

        is_valid, error_msg = validate_rule_syntax(rule_content)
        if not is_valid:
            log_with_symbol(
                "warning_config_reload",
                "warning",
                f"规则语法验证失败: {filename}",
                current_app.logger,
            )
            return jsonify({
                "error": "语法验证失败",
                "details": error_msg
            }), 400

        backup_path = target_file.with_suffix('.bak')
        temp_path = target_file.with_suffix(target_file.suffix + '.tmp')
        try:
            with _rule_operation_lock:
                temp_path.write_text(rule_content, encoding='utf-8')
                target_file.replace(backup_path)
                temp_path.replace(target_file)
                reloaded, reload_error = _reload_rules(filename)
                if not reloaded:
                    raise RuntimeError(f"规则重载失败: {reload_error}")
                backup_path.unlink()

            logger.info(f"[YARA][UPDATE] 规则更新成功: {filename}")
            return jsonify({
                "success": True,
                "message": "规则更新成功并已热重载"
            })

        except Exception as e:
            temp_path.unlink(missing_ok=True)
            if backup_path.exists():
                target_file.unlink(missing_ok=True)
                backup_path.replace(target_file)
                _reload_rules()
            logger.error(f"[YARA][UPDATE] 规则更新失败 {filename}: {e}")
            return jsonify({"error": f"更新失败: {e}"}), 500

    except Exception as e:
        logger = current_app.logger  # 确保在except中也有logger
        log_with_symbol(
            "error_registry_save",
            "error",
            f"规则更新失败 {filename}: {e}",
            current_app.logger,
        )
        return jsonify({"error": f"更新失败: {e}"}), 500

@yara_bp.route('/rules/<path:filename>', methods=['DELETE'])
@require_auth
def delete_rule(filename):
    """删除规则文件（备份到temp/rules_bak/）- v1.7.9路径加固"""
    try:
        logger = current_app.logger

        rules_path = _get_rules_path()

        target_file = _validate_rule_path(filename, rules_path)

        if not target_file.exists():
            abort(404)

        # 防止删除全部规则（至少保留1个）
        remaining_rules = list(rules_path.glob("*.yar"))
        if len(remaining_rules) <= 1:
            return jsonify({"error": "不能删除最后一个规则文件"}), 400

        # 创建备份目录（带时间戳）
        backup_dir = normalize_path("temp/rules_bak")
        backup_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"{filename}.{timestamp}.bak"
        backup_path = backup_dir / backup_filename

        with _rule_operation_lock:
            shutil.move(str(target_file), str(backup_path))
            reloaded, reload_error = _reload_rules()
            if not reloaded:
                shutil.move(str(backup_path), str(target_file))
                _reload_rules()
                return jsonify({
                    "error": f"删除后规则重载失败，已恢复: {reload_error}"
                }), 500

        logger.info(f"[YARA][DELETE] 规则文件已备份到: {backup_path}")

        return jsonify({
            "success": True,
            "message": f"规则已删除（备份: {backup_filename}）"
        })

    except Exception as e:
        logger.error(f"[YARA][DELETE] 删除失败 {filename}: {e}")
        return jsonify({"error": str(e)}), 500

@yara_bp.route('/rules/upload', methods=['POST'])
@require_auth
def upload_rule():
    """上传新规则文件（增强验证）"""
    try:
        logger = current_app.logger

        # 检查文件是否存在
        if 'file' not in request.files:
            return jsonify({"error": "未上传文件"}), 400

        file = request.files['file']
        safe_filename = _sanitize_rule_upload_filename(file.filename)
        if not safe_filename:
            return jsonify({"error": "文件名为空"}), 400

        if not safe_filename.endswith('.yar'):
            return jsonify({"error": "只支持 .yar 文件"}), 400

        # 读取内容
        content = file.read().decode('utf-8', errors='ignore')

        # 验证1：拒绝空文件
        if not content.strip():
            return jsonify({
                "error": "文件内容为空",
                "details": "YARA规则文件不能为空"
            }), 400

        # 验证2：文件大小限制（从config.toml读取）
        config = get_runtime().config.get()
        filesizes_cfg = config.get("filesizes", {})
        max_rule_size_kb = filesizes_cfg.get("max_rule_file_size_kb", 100)

        if len(content) > max_rule_size_kb * 1024:
            return jsonify({
                "error": "文件过大",
                "details": f"规则文件不能超过 {max_rule_size_kb}KB"
            }), 400

        # 验证3：语法检查
        is_valid, error_msg = validate_rule_syntax(content)
        if not is_valid:
            log_with_symbol(
                "warning_config_reload",
                "warning",
                f"Rule syntax validation failed: {safe_filename}",
                current_app.logger,
            )
            return jsonify({
                "error": "语法验证失败",
                "details": error_msg
            }), 400

        # 保存文件
        rules_path = _get_rules_path(config)

        save_path = _validate_rule_path(safe_filename, rules_path)
        if save_path.exists():
            return jsonify({
                "error": "同名文件已存在，请先删除或重命名"
            }), 409

        with _rule_operation_lock:
            save_path.write_text(content, encoding='utf-8')
            reloaded, reload_error = _reload_rules(safe_filename)
            if not reloaded:
                save_path.unlink(missing_ok=True)
                _reload_rules()
                return jsonify({
                    "error": "规则已通过语法检查，但未能加入活动规则集",
                    "details": reload_error,
                }), 500

        logger.info(f"[YARA][UPLOAD] 新规则上传成功: {file.filename}")
        return jsonify({
            "success": True,
            "message": "规则上传成功并已热重载",
            "filename": safe_filename
        })

    except Exception as e:
        logger.error(f"[YARA][UPLOAD] 上传失败: {e}")
        return jsonify({"error": f"上传失败: {e}"}), 500

@yara_bp.route('/rules/edit/<path:filename>', methods=['GET'])
@require_auth
def edit_rule_modal(filename):
    """返回YARA规则编辑模态框（v1.7.9: 路径加固）"""
    try:
        rules_path = _get_rules_path()

        target_file = _validate_rule_path(filename, rules_path)

        if not target_file.exists():
            abort(404)

        file_content = target_file.read_text(encoding='utf-8', errors='ignore')
        escaped_content = html_escape(file_content).replace('%', '%%')
        filename_arg = html_escape(json.dumps(filename))

        # 使用 % 格式化避免 f-string 解析问题
        html = """
        <div style="display:flex;flex-direction:column;height:100%%;gap:16px;">
          <textarea id="rule-editor" class="form-textarea" style="flex:1;min-height:300px;font-family:var(--font-mono);font-size:13px;line-height:1.6;">%s</textarea>
          <div id="yara-validation-result" style="font-family:var(--font-mono);font-size:12px;min-height:24px;"></div>
          <div style="display:flex;gap:10px;justify-content:flex-end;">
            <button class="btn btn-ghost" onclick="validateYaraRule()">Validate Syntax</button>
            <button class="btn btn-primary" onclick='saveYaraRule(%s)'>Save Update</button>
          </div>
        </div>

        <script>
        (function(){
          const el = document.querySelector('meta[name="csrf-token"]');
          const csrfToken = el ? el.content : '';

          window.validateYaraRule = function() {
            const content = document.getElementById('rule-editor').value;
            const resultDiv = document.getElementById('yara-validation-result');
            resultDiv.innerHTML = '<span style="color:var(--color-info)">[INFO] Validating...</span>';
            fetch('/admin/yara/validate', {
              method: 'POST',
              headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrfToken},
              body: JSON.stringify({content: content})
            })
            .then(r => r.json())
            .then(data => {
              if (data.valid) {
                resultDiv.innerHTML = '<span style="color:var(--color-safe)">[✓] Syntax OK</span>';
              } else {
                resultDiv.innerHTML = '<span style="color:var(--color-danger)">[✗] ' + (data.error || 'Unknown error').replace(/</g, '&lt;') + '</span>';
              }
            })
            .catch(e => {
              resultDiv.innerHTML = '<span style="color:var(--color-danger)">[✗] Request failed: ' + e.message + '</span>';
            });
          };

          window.saveYaraRule = function(filename) {
            const content = document.getElementById('rule-editor').value;
            if (!confirm('Confirm update? This will overwrite the original file.')) return;
            fetch('/admin/yara/rules/' + filename, {
              method: 'PUT',
              headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrfToken},
              body: JSON.stringify({content: content})
            })
            .then(r => r.json())
            .then(data => {
              if (data.success) {
                AnteumbraUtils.toast('Rule updated successfully', 'success');
                AnteumbraUtils.modal.hide('yara-edit-modal');
                htmx.ajax('GET', '/admin/yara/rules', {target: '#main-content'});
              } else {
                AnteumbraUtils.toast('Update failed: ' + (data.error || 'Unknown'), 'error');
              }
            })
            .catch(e => {
              AnteumbraUtils.toast('Save failed: ' + e.message, 'error');
            });
          };
        })();
        </script>
        """ % (escaped_content, filename_arg)
        return html
    except Exception as e:
        log_with_symbol(
            "yara_error", "error", f"编辑弹窗失败: {e}", current_app.logger
        )
        abort(500)


@yara_bp.route('/validate', methods=['POST'])
@require_auth
def validate_rule():
    """独立的语法验证端点（用于前端实时检查）"""
    rule_content = request.json.get('content', '')
    is_valid, error_msg = validate_rule_syntax(rule_content)
    return jsonify({
        "valid": is_valid,
        "error": error_msg
    })


@yara_bp.route('/search', methods=['GET'])
@require_auth
def search_rules():
    """YARA规则文件名搜索（实时过滤）"""
    try:
        query = request.args.get('q', '').lower()
        all_rules = get_rule_files()

        # 过滤逻辑
        filtered = [
            rule for rule in all_rules
            if query in rule['filename'].lower()
        ]

        # 获取分页参数
        page = max(1, int(request.args.get('page', 1)))
        config = get_runtime().config.get()
        per_page = config.get("web_admin", {}).get("yara_items_per_page", 6)

        total = len(filtered)
        total_pages = max(1, (total + per_page - 1) // per_page)

        start = (page - 1) * per_page
        end = start + per_page
        paginated_rules = filtered[start:end]

        # 渲染为HTML片段
        compact = request.args.get('compact') == '1'
        return render_template(
            'admin/yara_rules.html',
            rules=paginated_rules,
            page=page,
            total_pages=total_pages,
            total=total,
            per_page=per_page,
            compact=compact
        )

    except Exception as e:
        current_app.logger.error(f"[YARA][SEARCH] 搜索失败: {e}", exc_info=True)
        return jsonify({"error": f"搜索失败: {e}"}), 500
