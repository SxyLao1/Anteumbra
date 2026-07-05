# -*- coding: utf-8 -*-
"""
v1.9.4: WAF Adapters — ModSecurity / Cloudflare / AWS / Syslog

每个适配器实现 Plugin + EventSource 接口，
通过 PluginManager 统一加载和生命周期管理。
"""

from anteumbra.plugins.waf_adapters.modsecurity_adapter import ModSecurityAdapter
from anteumbra.plugins.waf_adapters.cloudflare_adapter import CloudflareAdapter
from anteumbra.plugins.waf_adapters.aws_adapter import AWSWAFAdapter
from anteumbra.plugins.waf_adapters.syslog_receiver import SyslogWAFReceiver

__all__ = [
    "ModSecurityAdapter",
    "CloudflareAdapter",
    "AWSWAFAdapter",
    "SyslogWAFReceiver",
]
