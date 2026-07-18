# -*- coding: utf-8 -*-
"""
v1.9.0: 主动手动扫描引擎

遍历用户配置的 Web 目录，使用现有 YARA/Static 扫描器逐文件扫描。
与 Registry 交叉比对去重，区分为"新发现"（首次检出）和"已知"（曾被动检测）。

架构：
  ManualScanner.scan_directory()
    → 遍历目录文件
    → quick_scan_yara() 现有扫描链
    → Registry path_to_key() 去重
    → 新发现自动 add(detection_source="active")
    → progress_callback 进度回调 → 供 SSE 推送
"""
import hashlib
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set
from anteumbra.domain.site import SiteIdentity
from anteumbra.domain.runtime import ConfigProviderPort, MetricsPort
from anteumbra.infrastructure.utils.path_utils import normalize_path, path_to_key

logger = logging.getLogger("monitor.manual_scanner")


@dataclass
class ManualScanResult:
    """单次手动扫描的完整结果"""
    scan_id: str
    target_dir: str
    start_time: float
    end_time: float = 0.0
    status: str = "pending"        # pending | running | completed | cancelled | error
    total_files: int = 0
    scanned_files: int = 0
    new_findings: int = 0           # 命中规则 且 不在 Registry
    known_findings: int = 0         # 命中规则 且 已在 Registry
    clean: int = 0
    errors: int = 0
    findings: List[Dict] = field(default_factory=list)
    error_message: str = ""
    site_id: str = ""
    site_name: str = ""


class ManualScanner:
    """主动扫描器 — 遍历目录，对每个文件运行扫描链，与 Registry 去重"""

    def __init__(
        self,
        app_logger=None,
        site_id: Optional[str] = None,
        site_name: Optional[str] = None,
        *,
        config_provider: ConfigProviderPort,
        scanner_service,
        metrics: MetricsPort,
    ):
        self.logger = app_logger or logger
        self._known_paths: Set[str] = set()
        self._registry_records: Dict[str, Dict] = {}
        self._site_id = site_id
        self._site_name = site_name
        self.config_provider = config_provider
        self.scanner_service = scanner_service
        self.metrics = metrics

    def _build_known_index(self):
        """预加载 Registry 全部记录到内存索引，O(1) 去重查找"""
        try:
            from anteumbra.infrastructure.suspicious_registry import get_all
        except ImportError:
            self.logger.warning("[MANUAL_SCANNER] 无法导入 suspicious_registry，去重功能不可用")
            return

        records = get_all(include_deleted=True, site_id=self._site_id)
        self._known_paths.clear()
        self._registry_records.clear()
        for r in records:
            key = r.get("file_path", "").lower()
            if key:
                self._known_paths.add(key)
                self._registry_records[key] = r
        self.logger.info(f"[MANUAL_SCANNER] 已知索引: {len(self._known_paths)} 条记录")

    def scan_directory(
        self,
        target_dir: Path,
        recursive: bool = True,
        extensions: Optional[List[str]] = None,
        progress_callback: Optional[Callable[["ManualScanResult"], None]] = None,
        cancelled_check: Optional[Callable[[], bool]] = None,
        site_id: Optional[str] = None,
        site_name: Optional[str] = None,
    ) -> ManualScanResult:
        """
        遍历目录扫描所有文件。

        Args:
            target_dir: 要扫描的目标目录
            recursive: 是否递归子目录
            extensions: 限定的文件扩展名列表（None 则默认 monitor_extensions）
            progress_callback: 进度回调，每 N 个文件调用一次
            cancelled_check: 取消检查回调，返回 True 时中断扫描

        Returns:
            ManualScanResult 包含完整统计和发现列表
        """
        scan_id = hashlib.sha256(
            f"{target_dir}:{time.time()}:{uuid.uuid4().hex[:8]}".encode()
        ).hexdigest()[:16]

        result = ManualScanResult(
            scan_id=scan_id,
            target_dir=str(target_dir),
            start_time=time.time(),
            status="running",
        )

        # ── 规范化目录 ──
        try:
            target = normalize_path(target_dir)
        except Exception:
            target = Path(str(target_dir))
        if not target.exists():
            result.status = "error"
            result.end_time = time.time()
            result.errors = 1
            result.error_message = f"目录不存在: {target_dir}"
            return result
        if not target.is_dir():
            result.status = "error"
            result.end_time = time.time()
            result.errors = 1
            result.error_message = f"路径不是目录: {target_dir}"
            return result

        # ── 默认扩展名 ──
        website = None
        try:
            identity = self.config_provider.resolve_site_identity(
                str(target),
                site_id=site_id or self._site_id,
                site_name=site_name or self._site_name,
            )
            website = self.config_provider.get_website(identity.site_id)
        except Exception:
            identity = SiteIdentity.from_values(
                site_id or self._site_id,
                site_name or self._site_name or "Legacy / unassigned",
            )
        self._site_id = identity.site_id
        self._site_name = identity.site_name
        result.site_id = identity.site_id
        result.site_name = identity.site_name

        if extensions is None:
            if website is not None:
                extensions = list(website.scan_options.monitor_extensions)
            else:
                extensions = None
        if extensions is None:
            cfg = self.config_provider.get()
            extensions = cfg.get("paths", {}).get(
                "monitor_extensions", [".php", ".asp", ".aspx", ".jsp", ".jspx"]
            )

        # ── 排除目录 ──
        # A manual scan uses the selected site's policy. An unassigned path
        # intentionally receives only conservative defaults, never another
        # site's [website] table.
        if website is not None:
            exclude_dirs = {
                str(directory).lower()
                for directory in website.scan_options.exclude_dirs
            }
        else:
            exclude_dirs = {"cache", "logs", "temp", "data", ".git"}

        # ── 构建已知索引 ──
        self._build_known_index()

        # ── 收集文件列表 ──
        ext_set = {e.lower() for e in extensions}
        file_list: List[Path] = []

        if recursive:
            for root, dirs, files in os.walk(target):
                # 过滤排除目录
                dirs[:] = [
                    directory
                    for directory in dirs
                    if directory.lower() not in exclude_dirs
                    and not directory.startswith(".")
                ]
                for f in files:
                    fp = Path(root) / f
                    if fp.suffix.lower() in ext_set:
                        file_list.append(fp)
        else:
            for f in target.iterdir():
                if f.is_file() and f.suffix.lower() in ext_set:
                    file_list.append(f)

        result.total_files = len(file_list)
        self.logger.info(
            f"[MANUAL_SCANNER] 扫描开始: {target_dir} | {result.total_files} 文件 | "
            f"扩展名: {extensions} | 递归: {recursive}"
        )

        # ── 逐文件扫描 ──
        progress_interval = max(1, result.total_files // 50)  # 每 2% 回调一次
        if website is not None:
            scan_options = website.scan_options
        else:
            from anteumbra.infrastructure.models import ScanOptions

            scan_options = ScanOptions(
                monitor_extensions=list(extensions),
                exclude_dirs=sorted(exclude_dirs),
            )

        for idx, file_path in enumerate(file_list):
            # 检查取消
            if cancelled_check and cancelled_check():
                result.status = "cancelled"
                result.end_time = time.time()
                self.logger.info(f"[MANUAL_SCANNER] 扫描已取消: {result.scanned_files}/{result.total_files}")
                return result

            result.scanned_files = idx + 1

            try:
                # ── 去重检查 ──
                norm_key = path_to_key(file_path).lower()
                is_known = norm_key in self._known_paths

                # ── 扫描 ──
                scan_result = self.scanner_service.scan(
                    file_path,
                    scan_options,
                    self.logger,
                )
                self.metrics.increment_site("scan_total", self._site_id)

                if scan_result and scan_result.is_suspicious:
                    scan_result.detection_source = "active"

                    if is_known:
                        # 已在 Registry → 已知发现
                        result.known_findings += 1
                        existing = self._registry_records.get(norm_key, {})
                        result.findings.append({
                            "file_path": str(file_path),
                            "file_name": file_path.name,
                            "classification": "known",
                            "engine": scan_result.engine,
                            "features": scan_result.features,
                            "score": scan_result.score,
                            "detected_at": existing.get("detected_at", "N/A"),
                            "quarantine_id": existing.get("quarantine_id", ""),
                            "detection_source": existing.get("detection_source", "passive"),
                            "site_id": self._site_id,
                            "site_name": self._site_name,
                        })
                    else:
                        # 不在 Registry → 新发现！自动注册
                        result.new_findings += 1
                        try:
                            from anteumbra.infrastructure.suspicious_registry import add
                            add(file_path, scan_result.features,
                                first_seen_ip="127.0.0.1",
                                detection_source="active",
                                site_id=self._site_id,
                                site_name=self._site_name)
                            # 立即更新索引，避免同次扫描重复记录
                            self._known_paths.add(norm_key)
                            self._registry_records[norm_key] = {
                                "file_path": norm_key,
                                "detected_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                "features": scan_result.features,
                                "quarantine_id": "",
                                "detection_source": "active",
                                "site_id": self._site_id,
                                "site_name": self._site_name,
                            }
                        except Exception as add_err:
                            self.logger.warning(
                                f"[MANUAL_SCANNER] 注册失败: {file_path} | {add_err}")
                            result.errors += 1

                        result.findings.append({
                            "file_path": str(file_path),
                            "file_name": file_path.name,
                            "classification": "new",
                            "engine": scan_result.engine,
                            "features": scan_result.features,
                            "score": scan_result.score,
                            "detected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "quarantine_id": "",
                            "detection_source": "active",
                            "site_id": self._site_id,
                            "site_name": self._site_name,
                        })

                    self.logger.debug(
                        f"[MANUAL_SCANNER] {'KNOWN' if is_known else 'NEW'}: "
                        f"{file_path.name} | {scan_result.engine}"
                    )

                else:
                    # 未命中规则 → clean
                    result.clean += 1

            except Exception as file_error:
                result.errors += 1
                self.logger.warning(f"[MANUAL_SCANNER] 扫描错误: {file_path} | {file_error}")

            # ── 进度回调 ──
            if progress_callback and idx % progress_interval == 0:
                try:
                    progress_callback(result)
                except Exception:
                    logger.debug("Progress callback failed during scan_directory", exc_info=True)

        # ── 完成 ──
        result.status = "completed"
        result.end_time = time.time()
        elapsed = round(result.end_time - result.start_time, 1)
        self.logger.info(
            f"[MANUAL_SCANNER] 扫描完成: {result.scanned_files}/{result.total_files} | "
            f"新发现:{result.new_findings} 已知:{result.known_findings} "
            f"clean:{result.clean} 错误:{result.errors} | 耗时:{elapsed}s"
        )

        # 最后一次回调
        if progress_callback:
            try:
                progress_callback(result)
            except Exception:
                logger.debug("Final progress callback failed in scan_directory", exc_info=True)

        return result
