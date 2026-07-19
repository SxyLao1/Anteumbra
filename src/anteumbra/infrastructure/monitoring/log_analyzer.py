# -*- coding: utf-8 -*-
"""
@Time: 1/5/2026 2:10 PM
@Auth: SxyLao1
@File: log_analyzer.py
@IDE: PyCharm
@Motto: HACK THE REAL
v1.7.4增强：通配符`**/access.log`完整递归支持 + 符号配置化日志
"""
import re
import logging
import os
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict
import glob
from anteumbra.infrastructure.models import Website
from anteumbra.infrastructure.utils.path_utils import normalize_path
# v1.7.4新增：导入符号化日志接口（铁律19）
from anteumbra.domain.logging import log_with_symbol


def resolve_access_log_path(access_log_path_cfg: str) -> Optional[Path]:
    """Resolve a fixed or globbed access-log path to the newest matching file."""
    if not access_log_path_cfg:
        return None

    if "**" in access_log_path_cfg:
        matches = glob.glob(access_log_path_cfg, recursive=True)
    elif "*" in access_log_path_cfg:
        matches = glob.glob(access_log_path_cfg)
    else:
        fixed_path = normalize_path(access_log_path_cfg)
        return fixed_path if fixed_path.exists() else None

    existing = [Path(path) for path in matches if Path(path).exists()]
    if not existing:
        return None
    return normalize_path(sorted(existing, key=lambda p: p.stat().st_mtime, reverse=True)[0])


class LogAnalyzer:
    """Web访问日志分析器（v1.7.4增强：通配符递归支持）"""

    LOG_PATTERNS = [
        r'(?P<ip>\S+)\s+\S+\s+\S+\s*\[(?P<time>[^\]]+)\]\s*"(?P<method>\w+)\s+(?P<url>[^ ]+)\s+[^"]+"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)',
        r'(?P<ip>\S+)\s+\S+\s+\S+\s*\[(?P<time>[^\]]+)\]\s*"(?P<method>\w+)\s+(?P<url>[^ ]+)\s+[^"]+"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)\s+"[^"]*"\s+"[^"]*"'
    ]

    def __init__(self, website: Website, logger: logging.Logger):
        self.website = website
        self.logger = logger
        self.log_path: Optional[Path] = None

        # ============================================================================
        # v1.7.4关键修复：初始化时立即设置log_path并验证通配符支持
        # ============================================================================
        self.log_path = self.get_configured_path()
        self.log_type = self._detect_log_type()

        # 如果是通配符路径，记录详细解析日志
        if "*" in str(self.website.scan_options.access_log_path):
            log_with_symbol("notice", "info",
                            f"通配符路径解析: {self.website.scan_options.access_log_path} -> {self.log_path}",
                            self.logger)

    def _detect_log_type(self) -> str:
        log_path = str(self.log_path).lower()
        if "nginx" in log_path:
            return "nginx"
        if "tomcat" in log_path or "localhost_access_log" in log_path:
            return "tomcat"
        return "apache"

    def get_configured_path(self) -> Optional[Path]:
        """
        v1.7.4增强：读取运维配置的日志路径，支持通配符`**/access.log`完整递归

        改进点：
        1. 支持 `**/access.log` 任意层级递归匹配
        2. 支持 `/var/log/**/access.log` 限定父目录的递归
        3. 自动选择最新修改时间的匹配文件
        4. 增强错误日志输出（符号化）
        """
        self.logger.debug("[LOG][SEARCH] 正在读取配置的日志路径...")

        # 从Website配置读取（优先使用scan_options中的配置）
        access_log_path_cfg = getattr(self.website.scan_options, 'access_log_path', None)

        # 如果scan_options中没有，尝试从全局配置读取
        if not access_log_path_cfg:
            log_config = getattr(self.website, "log_config", {}) or {}
            access_log_path_cfg = log_config.get("access_log_path", "").strip()

        if not access_log_path_cfg:
            log_with_symbol("warning_config_reload", "warning", "access_log_path未配置", self.logger)
            return None

        # ============================================================================
        # 策略1: 递归通配符匹配（支持 **/access.log）
        # ============================================================================
        if "**" in access_log_path_cfg:
            try:
                # 必须指定recursive=True（Python 3.5+支持）
                matches = glob.glob(access_log_path_cfg, recursive=True)
                if not matches:
                    log_with_symbol("warning_config_reload", "warning",
                                    f"通配符路径无匹配: {access_log_path_cfg}", self.logger)
                    return None

                # 按修改时间降序排序，选择最新的文件
                sorted_matches = sorted(matches, key=lambda p: Path(p).stat().st_mtime, reverse=True)
                selected_path = normalize_path(sorted_matches[0])

                log_with_symbol("success", "info",
                                f"通配符匹配成功: {len(matches)}个文件，选择最新: {selected_path.name}", self.logger)

                return selected_path

            except Exception as e:
                log_with_symbol("error_scan_fail", "error",
                                f"通配符解析失败: {access_log_path_cfg} - {e}", self.logger)
                return None

        # ============================================================================
        # 策略2: 单级通配符匹配（保持向后兼容）
        # ============================================================================
        elif "*" in access_log_path_cfg:
            try:
                matches = glob.glob(access_log_path_cfg)
                if not matches:
                    log_with_symbol("warning_config_reload", "warning",
                                    f"通配符路径无匹配: {access_log_path_cfg}", self.logger)
                    return None

                selected_path = normalize_path(sorted(matches, key=lambda p: Path(p).stat().st_mtime, reverse=True)[0])
                log_with_symbol("success", "info",
                                f"通配符匹配: {len(matches)}个文件，选择: {selected_path.name}", self.logger)
                return selected_path

            except Exception as e:
                log_with_symbol("error_scan_fail", "error",
                                f"通配符解析失败: {access_log_path_cfg} - {e}", self.logger)
                return None

        # ============================================================================
        # 策略3: 固定路径（无通配符）
        # ============================================================================
        else:
            fixed_path = normalize_path(access_log_path_cfg)
            if not fixed_path.exists():
                log_with_symbol("warning_config_reload", "warning",
                                f"日志文件不存在: {fixed_path}", self.logger)
                return None

            log_with_symbol("success", "info", f"固定路径加载: {fixed_path}", self.logger)
            return fixed_path

    def extract_ip(self, log_entry: str) -> Optional[str]:
        """提取IP地址（修复版）"""
        for pattern in self.LOG_PATTERNS:
            match = re.match(pattern, log_entry)
            if match:
                ip = match.group("ip")

                # 修复：正确读取配置中的filter_internal_ip
                log_config = getattr(self.website, "log_config", {}) or {}
                filter_internal = log_config.get("filter_internal_ip", False)

                if filter_internal and self._is_internal_ip(ip):
                    log_with_symbol("debug_exclude", "debug", f"过滤内网IP: {ip}", self.logger)
                    return None

                return ip
        return None

    def _is_internal_ip(self, ip: str) -> bool:
        """判断是否为内网IP"""
        if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
            return True
        if ip.startswith("172."):
            second_octet = int(ip.split(".")[1])
            return 16 <= second_octet <= 31
        return False

    def analyze_shell_access(self, shell_path: Path, time_window_minutes: int = 0) -> Optional[Dict]:
        """
        分析Webshell访问日志（v1.6.6 - 纯URL匹配，无时间窗口限制）

        v1.7.4增强：增加通配符匹配日志的稳定性
        """
        if not self.log_path:
            log_with_symbol("debug_scan", "debug", "未配置日志路径", self.logger)
            return None

        log_with_symbol("scan_hit", "info", f"开始全量扫描: {self.log_path.name}", self.logger)

        # 如果log_path是通过通配符获取的，在分析前重新验证文件存在性
        if not self.log_path.exists():
            log_with_symbol("warning_wal_fail", "warning",
                            f"日志文件已不存在，尝试重新解析通配符: {self.website.scan_options.access_log_path}",
                            self.logger)

            # 重新执行通配符解析
            new_path = self.get_configured_path()
            if new_path and new_path != self.log_path:
                self.log_path = new_path
                log_with_symbol("success", "info", f"切换到新日志文件: {self.log_path.name}", self.logger)
            else:
                log_with_symbol("error_scan_fail", "error", "无法找到有效的日志文件", self.logger)
                return None

        suspicious_ips = {}
        try:
            # Windows共享模式读取
            if sys.platform == "win32":
                def share_mode_opener(filepath, flags):
                    return os.open(filepath, os.O_RDONLY | os.O_BINARY)

                f = open(self.log_path, 'r', encoding='utf-8', errors='ignore',
                         buffering=1, opener=share_mode_opener)
            else:
                f = open(self.log_path, 'r', encoding='utf-8', errors='ignore', buffering=1)

            with f:
                for line_num, line in enumerate(f, 1):
                    ip = self.extract_ip(line)
                    if not ip:
                        continue

                    # 匹配URL路径
                    if f"/{shell_path.name}" in line:
                        suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1
                        log_with_symbol("debug_scan", "debug",
                                        f"第{line_num}行: {ip} -> {shell_path.name}", self.logger)

            log_with_symbol("scan_hit", "info", f"发现 {len(suspicious_ips)} 个可疑IP", self.logger)

        except Exception as e:
            log_with_symbol("error_scan_fail", "error", f"分析失败: {e}", self.logger)

        return {
            "shell_path": str(shell_path),
            "analysis_mode": "URL路径匹配（无时间窗口）",
            "suspicious_ips": suspicious_ips,
            "log_path": str(self.log_path),
        }

    def _parse_log_time(self, log_line: str) -> Optional[datetime]:
        """从日志行解析时间（备用）"""
        for pattern in self.LOG_PATTERNS:
            match = re.match(pattern, log_line)
            if match:
                time_str = match.group("time")
                try:
                    return datetime.strptime(time_str.split()[0], "%d/%B/%Y:%H:%M:%S")
                except ValueError:
                    try:
                        return datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        return None
        return None


def get_analyzer(website: Website, logger: logging.Logger) -> 'LogAnalyzer':
    """获取分析器实例"""
    return LogAnalyzer(website, logger)
