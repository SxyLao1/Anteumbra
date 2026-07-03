# -*- coding: utf-8 -*-
"""
@Time: 1/11/2026 9:59 PM
@Auth: SxyLao1
@File: __init__.py.py
@IDE: PyCharm
@Motto: HACK THE REAL
Blueprint统一注册
"""
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flask import Flask


def register_blueprints(app: 'Flask'):
    """注册所有Blueprint — v1.9.0 拆分后共 9 个独立 Blueprint"""
    # 核心 Blueprint（Metrics / Admin / YARA / Quarantine）
    from anteumbra.interfaces.web.blueprints.metrics import metrics_bp
    app.register_blueprint(metrics_bp)

    from anteumbra.interfaces.web.blueprints.admin_bp import admin_bp
    app.register_blueprint(admin_bp)

    from anteumbra.interfaces.web.blueprints.yara_bp import yara_bp
    app.register_blueprint(yara_bp)

    from anteumbra.interfaces.web.blueprints.quarantine_bp import quarantine_bp
    app.register_blueprint(quarantine_bp)

    # v1.9.0: 拆分 Blueprint（从 admin_bp.py 分离）
    from anteumbra.interfaces.web.blueprints.scanner_bp import scanner_bp
    app.register_blueprint(scanner_bp)

    from anteumbra.interfaces.web.blueprints.blocklist_bp import blocklist_bp
    app.register_blueprint(blocklist_bp)

    from anteumbra.interfaces.web.blueprints.profiles_bp import profiles_bp
    app.register_blueprint(profiles_bp)

    from anteumbra.interfaces.web.blueprints.records_bp import records_bp
    app.register_blueprint(records_bp)

    # v1.0.6: Blueprint split from admin_bp (settings / monitor / system)
    from anteumbra.interfaces.web.blueprints.settings_bp import settings_bp
    app.register_blueprint(settings_bp)

    from anteumbra.interfaces.web.blueprints.monitor_bp import monitor_bp
    app.register_blueprint(monitor_bp)

    from anteumbra.interfaces.web.blueprints.system_bp import system_bp
    app.register_blueprint(system_bp)