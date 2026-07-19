# -*- coding: utf-8 -*-
"""
@Time: 1/5/2026 9:40 PM
@Auth: SxyLao1
@File: log_monitor.py
@IDE: PyCharm
@Motto: HACK THE REAL
v1.7.0重构：从配置读取冷却策略
"""
import logging
import threading
import sys
import time
import re
import os
from pathlib import Path
from threading import Thread
from typing import Optional, Dict, List
from anteumbra.domain.logging import log_with_symbol
from anteumbra.domain.runtime import (
    ConfigProviderPort,
    DetectionRegistryPort,
)
from anteumbra.domain.service_ports import NotifierPort
from anteumbra.infrastructure.monitoring.log_analyzer import LogAnalyzer
from anteumbra.infrastructure.monitoring.notifier import format_alert_message
from anteumbra.infrastructure.utils.path_utils import normalize_path

class LogMonitor:
    """日志监控器（v1.6.6 三层冷却策略）"""

    def __init__(
        self,
        logger,
        analyzer,
        *,
        config_provider: ConfigProviderPort,
        notifier: NotifierPort,
        registry: DetectionRegistryPort,
    ):
        self.logger = logger
        self.analyzer = analyzer
        self.config_provider = config_provider
        self.notifier = notifier
        self.registry = registry
        self.website = analyzer.website
        self.site_id = analyzer.website.site_id
        self._is_running = False
        self._thread: Optional[Thread] = None

        # v1.7.0重构：从配置读取三层冷却配置
        config = config_provider.get()
        log_monitor_cfg = config.get("thresholds", {})  # 复用thresholds段

        self._initial_cooldown = log_monitor_cfg.get("initial_alert_cooldown_seconds", 60.0)
        self._high_freq_threshold = log_monitor_cfg.get("high_frequency_threshold", 10)
        self._high_freq_cooldown = log_monitor_cfg.get("high_frequency_cooldown_seconds", 300.0)

        # 滑动窗口：记录最近1小时访问历史
        self._access_history: Dict[tuple, List[float]] = {}
        self._cooldown_cache: Dict[tuple, float] = {}  # 冷却状态缓存

        self._last_size = 0
        self._last_log_scan_complete = True

    def start(self):
        """启动监控（修复状态初始化）"""
        if self._is_running:
            log_with_symbol("log_monitor_skip_duplicate", "warning", f"重复启动，已忽略", self.logger)
            return

        self.log_path = self.analyzer.log_path
        if not self.log_path or not self.log_path.exists():
            log_with_symbol("log_monitor_start_error", "error", f"启动失败：日志文件不存在", self.logger)
            return

        self._last_size = self.log_path.stat().st_size
        self._current_inode = self.log_path.stat().st_ino
        self._last_log_scan_complete = True
        log_with_symbol("log_monitor_info", "info", f"初始化位置: {self._last_size} (跳过历史日志)", self.logger)

        self._is_running = True
        self._thread = Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        log_with_symbol("log_monitor_info", "info", f"监控线程已启动", self.logger)

    def stop(self):
        """停止监控"""
        self._is_running = False
        if self._thread:
            self._thread.join(timeout=2.0)

        log_with_symbol("log_monitor_stop", "info", f"停止监控", self.logger)

    @property
    def is_running(self) -> bool:
        return self._is_running

    def _monitor_loop(self):
        """监控循环（v1.6.6：增强容错与轮转检测）"""
        log_with_symbol("log_monitor_info", "info", f"开始监控循环", self.logger)
        while self._is_running:
            try:
                if not self.log_path or not self.log_path.exists():
                    log_with_symbol("log_monitor_start_error", "warning", f"日志文件不存在: {self.log_path}", self.logger)
                    self._last_log_scan_complete = False
                    time.sleep(5)
                    continue

                # 通配符轮转检测
                if "*" in str(self.analyzer.log_path):
                    latest_path = self.analyzer.get_configured_path()
                    if latest_path and latest_path != self.log_path:
                        if self._last_log_scan_complete:
                            log_with_symbol("log_monitor_info", "info", f"切换到新日志: {latest_path.name}", self.logger)
                            self.log_path = latest_path
                            self._last_size = 0
                            self._current_inode = self.log_path.stat().st_ino
                        else:
                            time.sleep(1)
                            continue

                stat_info = self.log_path.stat()
                current_size = stat_info.st_size
                current_inode = stat_info.st_ino

                if current_size > self._last_size:
                    self._last_log_scan_complete = False
                    new_bytes = current_size - self._last_size

                    # Windows共享模式读取
                    try:
                        if sys.platform == "win32":
                            def share_mode_opener(filepath, flags):
                                return os.open(filepath, os.O_RDONLY | os.O_BINARY)

                            with open(self.log_path, 'r', encoding='utf-8', errors='ignore',
                                      opener=share_mode_opener) as f:
                                f.seek(self._last_size)
                                new_content = f.read(new_bytes)
                        else:
                            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                                f.seek(self._last_size)
                                new_content = f.read(new_bytes)
                    except PermissionError as pe:
                        log_with_symbol("log_monitor_skip", "warning", f"权限不足，跳过: {pe}", self.logger)
                        self._last_log_scan_complete = True
                        time.sleep(1)
                        continue
                    except Exception as file_error:

                        log_with_symbol("log_monitor_error", "error", f"文件读取错误: {file_error}", self.logger)
                        self._last_log_scan_complete = True
                        time.sleep(1)
                        continue

                    if new_content.strip():
                        lines = new_content.splitlines()
                        for line in lines:
                            if line.strip():
                                self._process_line(line)  # v1.6.7修复：调用恢复的_process_line方法

                    self._last_size = current_size
                    self._last_log_scan_complete = True

                elif current_size < self._last_size:
                    log_with_symbol("log_monitor_warning", "warning", f"日志截断，重置: {current_size}", self.logger)
                    self._last_size = current_size
                    self._last_log_scan_complete = True

                time.sleep(1)

            except Exception as e:
                log_with_symbol("log_monitor_error", "error", f"循环错误: {e}", self.logger)
                self._last_log_scan_complete = True
                time.sleep(5)

    def _process_line(self, line: str):
        """处理单行日志 - v1.7.7：增强日志输出"""
        try:
            ip = self.analyzer.extract_ip(line)
            if not ip:
                return

            url_match = re.search(r'"(?:GET|POST) ([^ ]+) ', line)
            if not url_match:
                return

            access_url = url_match.group(1)

            # v1.7.7-CRITICAL：使用 INFO 级别确保日志一定显示
            self.logger.info(f"[LOG_MONITOR][URL] 访问: {access_url} | IP: {ip}")

            # 匹配可疑文件
            suspicious_files = self.registry.get_all(
                include_deleted=True, site_id=self.site_id
            )
            for record in suspicious_files:
                file_path = normalize_path(record["file_path"])
                file_name = file_path.name

                # 增强匹配逻辑
                if f"/{file_name}" in access_url or access_url.endswith(file_name):
                    # ============================================================================
                    # v1.7.7-CRITICAL：增加显式 Registry 更新标记
                    # ============================================================================
                    self.logger.critical(
                        f"[LOG_MONITOR][HIT] {file_name} 被 {ip} 访问 | "
                        f"[REGISTRY][UPDATE] 通信次数即将增加"
                    )

                    # 立即递增
                    self.registry.increment_access(
                        file_path, ip, site_id=self.site_id
                    )

                    # 三层冷却策略
                    alert_level, should_alert = self._check_alert_layers(file_path, ip, line)

                    if should_alert:
                        self._trigger_alert(record, ip, line, file_path, alert_level)
                    else:
                        self.logger.debug(f"[ALERT][COOLDOWN] {file_name} - {ip} 处于冷却中")

                    return  # 找到匹配后立即返回

        except Exception as e:
            log_with_symbol("log_monitor_error", "error", f"行处理失败: {e}", self.logger)

    def _check_alert_layers(self, file_path: Path, ip: str, log_line: str) -> tuple:
        """
        v1.7.3: 指数退避冷却策略（数学模型）

        Returns:
            (alert_level: str, should_alert: bool)
        """
        # 配置参数（从config.toml读取）
        config = self.config_provider.get()
        thresholds_cfg = config.get("thresholds", {})

        # 基础参数
        T_base = thresholds_cfg.get("initial_alert_cooldown_seconds", 60.0)  # 基础冷却60秒
        alpha = thresholds_cfg.get("cooldown_alpha", 0.1)  # 增长系数0.1
        beta = thresholds_cfg.get("cooldown_beta", 1.5)  # 等级乘数1.5
        gamma = thresholds_cfg.get("cooldown_gamma", 1.2)  # IP聚类惩罚系数1.2
        delta = thresholds_cfg.get("cooldown_delta", 1.3)  # 服务关联惩罚系数1.3

        # 自适应阈值（根据历史基线）
        base_threshold = thresholds_cfg.get("high_frequency_threshold", 10)
        adaptive_threshold = self._calculate_adaptive_threshold(file_path, ip, base_threshold)

        key = (str(file_path), ip)
        now = time.time()

        # 初始化访问历史
        if key not in self._access_history:
            self._access_history[key] = []

        # 清理过期记录（1小时窗口）
        self._access_history[key] = [
            ts for ts in self._access_history[key]
            if now - ts < 3600
        ]

        # 添加当前访问时间戳
        self._access_history[key].append(now)

        # 统计60秒内事件数
        recent_60s = [ts for ts in self._access_history[key] if now - ts < 60]
        N_events = len(recent_60s)

        # ===== 层级判定 =====

        # Level 3: APT持续攻击（同一IP连续3次高频）
        if self._is_apt_attack(file_path, ip, now):
            level = 3
            alert_level = "APT"
            T_cooldown = T_base * (1 + alpha * N_events) * (beta ** level) * gamma * delta
            self.logger.critical(f"[ALERT][APT] {file_path.name} - {ip} 持续攻击！冷却: {T_cooldown:.1f}秒")
            should_alert = self._is_cooling_expired(key, level, T_cooldown, now)
            return alert_level, should_alert

        # Level 2: 高频攻击（超过自适应阈值）
        if N_events >= adaptive_threshold:
            level = 2
            alert_level = "HIGH_FREQ"

            # 计算冷却时间（指数退避）
            T_cooldown = T_base * (1 + alpha * N_events) * (beta ** level)

            # IP聚类惩罚（如果是同一IP）
            if self._is_same_ip_cluster(ip, file_path):
                T_cooldown *= gamma
                alert_level = "HIGH_FREQ_IP_CLUSTER"

            # 服务关联惩罚（Webshell+数据库爆破）
            if self._is_service_combo(file_path, ip):
                T_cooldown *= delta
                alert_level = "HIGH_FREQ_COMBO"

            self.logger.critical(
                f"[ALERT][{alert_level}] {file_path.name} - {ip} 60秒访问{N_events}次！冷却: {T_cooldown:.1f}秒")
            should_alert = self._is_cooling_expired(key, level, T_cooldown, now)
            return alert_level, should_alert

        # Level 1: 首次告警冷却
        level = 1
        alert_level = "INITIAL"
        T_cooldown = T_base

        should_alert = self._is_cooling_expired(key, level, T_cooldown, now)
        if should_alert:
            self.logger.info(f"[ALERT][{alert_level}] {file_path.name} - {ip} 首次访问")

        return alert_level, should_alert

    def _calculate_adaptive_threshold(self, file_path: Path, ip: str, base_threshold: int) -> int:
        """自适应阈值计算（基于历史基线）"""
        # 获取该IP的历史攻击频率
        key = (str(file_path), ip)

        # 默认返回基础阈值
        if key not in self._access_history:
            return base_threshold

        # 计算该IP的平均访问频率
        history = self._access_history[key]
        if len(history) < 10:  # 数据不足，返回基础阈值
            return base_threshold

        # 计算最近1小时的平均访问间隔
        recent_1h = [ts for ts in history if time.time() - ts < 3600]
        if len(recent_1h) < 2:
            return base_threshold

        # 计算平均每秒访问次数
        intervals = [recent_1h[i + 1] - recent_1h[i] for i in range(len(recent_1h) - 1)]
        avg_interval = sum(intervals) / len(intervals)
        freq_per_minute = 60.0 / avg_interval if avg_interval > 0 else 0

        # 动态调整阈值：如果攻击频率高，提高阈值避免轰炸
        if freq_per_minute > base_threshold * 2:
            return int(base_threshold * 1.5)  # 提高50%

        return base_threshold

    def _is_apt_attack(self, file_path: Path, ip: str, now: float) -> bool:
        """检测APT持续攻击（同一IP连续3次高频）"""
        key = (str(file_path), ip)

        # 检查最近3次是否都超过阈值
        recent_alerts = [
            ts for ts in self._access_history.get(key, [])
            if now - ts < 180  # 3分钟内
        ]

        return len(recent_alerts) >= 3

    def _is_same_ip_cluster(self, ip: str, file_path: Path) -> bool:
        """IP聚类检测：同一IP在短时间内攻击多个文件"""
        # 统计该IP在60秒内访问的不同文件数
        now = time.time()
        accessed_files = set()

        for (file_key, ip_key), timestamps in self._access_history.items():
            if ip_key == ip:  # 同一IP
                recent = [ts for ts in timestamps if now - ts < 60]
                if recent:
                    accessed_files.add(file_key)

        # 如果访问了3个或以上不同文件，认为是IP聚类攻击
        return len(accessed_files) >= 3

    def _is_service_combo(self, file_path: Path, ip: str) -> bool:
        """服务关联检测：Webshell访问 + 数据库/系统文件访问"""
        # 检查该IP是否同时访问了Webshell和数据库爆破特征
        now = time.time()

        # 查找该IP的所有访问记录
        db_access = False
        shell_access = False

        for (file_key, ip_key), timestamps in self._access_history.items():
            if ip_key == ip:
                recent = [ts for ts in timestamps if now - ts < 60]
                if not recent:
                    continue

                # 检查是否是数据库相关文件
                db_indicators = ['db.php', 'mysql', 'config.php', 'database']
                if any(ind in file_key.lower() for ind in db_indicators):
                    db_access = True

                # 检查是否是真正的Webshell文件
                if file_key == str(file_path):  # 当前文件
                    shell_access = True

        return db_access and shell_access

    def _is_cooling_expired(self, key: tuple, level: int, T_cooldown: float, now: float) -> bool:
        """检查冷却是否过期"""
        cooldown_key = (key[0], key[1], f"LEVEL_{level}")

        if cooldown_key in self._cooldown_cache:
            last_alert = self._cooldown_cache[cooldown_key]
            if now - last_alert < T_cooldown:
                remaining = T_cooldown - (now - last_alert)
                self.logger.debug(f"[COOLDOWN] {key[1]} 剩余冷却: {remaining:.1f}秒")
                return False

        # 更新冷却状态
        self._cooldown_cache[cooldown_key] = now

        # 清理过期冷却记录（缓存超过1000条时）
        if len(self._cooldown_cache) > 1000:
            cutoff = now - 3600  # 清理1小时前的冷却记录
            self._cooldown_cache = {
                k: v for k, v in self._cooldown_cache.items() if v > cutoff
            }

        return True

    def _trigger_alert(self, record: Dict, attacker_ip: str, log_line: str,
                       file_path: Path, alert_level: str = "NORMAL"):
        """异步触发告警（增强版）"""
        try:
            # 标记已告警
            self.registry.mark_alerted(file_path, site_id=self.site_id)

            # 同步日志
            self.logger.critical("=" * 50)
            self.logger.critical(f"[ALERT][{alert_level}] WEBSHELL被访问: {file_path.name}")
            self.logger.critical(f"[ALERT][{alert_level}] 攻击IP: {attacker_ip}")
            self.logger.critical("=" * 50)

            # v1.8.4: 异步发送（使用统一消息构建器）
            def _send_async():
                try:
                    # 读取系统状态（隔离/封禁开关）
                    sys_status = {"auto_quarantine_enabled": True, "auto_block_enabled": False, "block_device_count": 0}
                    try:
                        cfg = self.config_provider.get()
                        sys_status["auto_quarantine_enabled"] = cfg.get("quarantine", {}).get("auto_quarantine_enabled", True)
                        blocker_cfg = cfg.get("ip_blocker", {})
                        sys_status["auto_block_enabled"] = blocker_cfg.get("auto_block_enabled", False)
                        sys_status["block_device_count"] = len(blocker_cfg.get("devices", []))
                    except Exception:
                        self.logger.debug("Failed to read system status config for alert context", exc_info=True)
                    ctx = {
                        "alert_type": "webshell_access",
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "file_path": str(file_path),
                        "attacker_ip": attacker_ip,
                        "alert_level": alert_level,
                        "level": alert_level,
                        "site_id": self.site_id,
                        "site_name": self.website.name,
                    }
                    ctx.update(sys_status)
                    message = format_alert_message(ctx)
                    self.notifier.send_alert(
                        message,
                        level=alert_level,
                        site_id=self.site_id,
                    )
                except Exception as e:
                    self.logger.error(f"[ALERT] Notification failed: {e}")

            threading.Thread(target=_send_async, daemon=True).start()

        except Exception as e:
            self.logger.error(f"[ALERT] 触发严重错误: {e}", exc_info=True)
