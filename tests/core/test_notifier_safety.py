"""Notification safety and observability regression tests."""

import logging


class FakeMetrics:
    def __init__(self):
        self.counters = {}
        self.outcomes = []
        self.site_counters = {}
        self.site_outcomes = []

    def increment(self, name, value=1, *, site_id=None):
        self.counters[name] = self.counters.get(name, 0) + value
        if site_id:
            bucket = self.site_counters.setdefault(site_id, {})
            bucket[name] = bucket.get(name, 0) + value

    def record_notification(self, status, error="", *, site_id=None):
        self.outcomes.append((status, error))
        self.site_outcomes.append((status, error, site_id))

    def record_wechat_failure(self, *, site_id=None):
        self.increment("wechat_failures", site_id=site_id)


def test_incomplete_enabled_channels_never_attempt_network(tmp_path, monkeypatch):
    from anteumbra.infrastructure.monitoring import notifier as notifier_module

    monkeypatch.chdir(tmp_path)
    smtp_calls = []
    monkeypatch.setattr(
        notifier_module.smtplib,
        "SMTP_SSL",
        lambda *_args, **_kwargs: smtp_calls.append(True),
    )
    metrics = FakeMetrics()

    notifier = notifier_module.Notifier(
        {
            "enabled": True,
            "email": {
                "enabled": True,
                "smtp_host": "smtp.example.test",
                "username": "",
                "password": "",
                "from_addr": "",
                "to_addrs": [],
            },
            "wechat": {"enabled": True, "send_key": ""},
        },
        logging.getLogger("test.notifier.incomplete"),
        metrics,
    )

    assert notifier.enabled is False
    assert notifier.channels["email"]["enabled"] is False
    assert notifier.channels["wechat"]["enabled"] is False
    assert notifier._alert_thread is None
    assert notifier.enqueue_alert("detected", "CRITICAL") is False
    assert smtp_calls == []
    assert metrics.counters["alert_total"] == 1
    assert metrics.outcomes[-1][0] == "skipped"


def test_notification_metrics_keep_the_originating_site(tmp_path, monkeypatch):
    from anteumbra.infrastructure.monitoring import notifier as notifier_module

    monkeypatch.chdir(tmp_path)
    metrics = FakeMetrics()
    notifier = notifier_module.Notifier(
        {"enabled": False}, logging.getLogger("test.notifier.site-metrics"), metrics
    )

    assert notifier.enqueue_alert("detected", site_id="alpha") is False
    assert metrics.site_counters["alpha"]["alert_total"] == 1
    assert metrics.site_outcomes[-1] == (
        "skipped",
        "no external channel is configured",
        "alpha",
    )


def test_notification_batch_never_combines_sites(tmp_path, monkeypatch):
    from anteumbra.infrastructure.monitoring import notifier as notifier_module

    monkeypatch.chdir(tmp_path)
    metrics = FakeMetrics()
    notifier = notifier_module.Notifier(
        {"enabled": False}, logging.getLogger("test.notifier.site-batch"), metrics
    )
    sent = []
    monkeypatch.setattr(
        notifier,
        "send_alert",
        lambda message, **kwargs: sent.append((message, kwargs)) or True,
    )

    notifier._dispatch_batch(
        [
            ("alpha alert", "CRITICAL", "alpha"),
            ("beta alert", "CRITICAL", "beta"),
        ]
    )

    assert [(message, kwargs["site_id"]) for message, kwargs in sent] == [
        ("alpha alert", "alpha"),
        ("beta alert", "beta"),
    ]


def test_successful_email_updates_notification_metrics(tmp_path, monkeypatch):
    from anteumbra.infrastructure.monitoring import notifier as notifier_module

    monkeypatch.chdir(tmp_path)
    metrics = FakeMetrics()

    class FakeSmtp:
        def __init__(self, *_args, **_kwargs):
            self.sent = False

        def login(self, _username, _password):
            return None

        def send_message(self, _message):
            self.sent = True

        def quit(self):
            return None

    monkeypatch.setattr(notifier_module.smtplib, "SMTP_SSL", FakeSmtp)

    notifier = notifier_module.Notifier(
        {
            "enabled": True,
            "email": {
                "enabled": True,
                "smtp_host": "smtp.example.test",
                "smtp_port": 465,
                "username": "sender",
                "password": "secret",
                "from_addr": "sender@example.test",
                "to_addrs": ["soc@example.test"],
                "use_ssl": True,
            },
        },
        logging.getLogger("test.notifier.email"),
        metrics,
    )

    try:
        assert notifier.send_alert("detected", "CRITICAL") is True
        assert metrics.counters["alert_total"] == 1
        assert [status for status, _ in metrics.outcomes] == ["attempted", "success"]
    finally:
        notifier._stop_alert_worker()

def test_email_transport_starts_tls_before_login(tmp_path, monkeypatch):
    from anteumbra.infrastructure.monitoring import notifier as notifier_module

    monkeypatch.chdir(tmp_path)
    calls = []

    class FakeSmtp:
        def __init__(self, *_args, **_kwargs):
            calls.append("connect")

        def starttls(self):
            calls.append("starttls")

        def login(self, _username, _password):
            calls.append("login")

        def send_message(self, _message):
            calls.append("send")

        def quit(self):
            calls.append("quit")

    monkeypatch.setattr(notifier_module.smtplib, "SMTP", FakeSmtp)
    notifier = notifier_module.Notifier(
        {
            "enabled": True,
            "email": {
                "enabled": True,
                "smtp_host": "smtp.example.test",
                "smtp_port": 587,
                "username": "sender",
                "password": "secret",
                "from_addr": "sender@example.test",
                "to_addrs": ["soc@example.test"],
                "use_tls": True,
                "use_ssl": False,
            },
        },
        logging.getLogger("test.notifier.starttls"),
        FakeMetrics(),
    )

    try:
        assert notifier.send_alert("detected", "CRITICAL") is True
        assert calls == ["connect", "starttls", "login", "send", "quit"]
    finally:
        notifier._stop_alert_worker()


def test_serverchan_circuit_breaker_uses_email_fallback(tmp_path, monkeypatch):
    from anteumbra.infrastructure.monitoring import notifier as notifier_module

    monkeypatch.chdir(tmp_path)
    notifier = notifier_module.Notifier(
        {
            "enabled": True,
            "circuit_breaker_threshold": 2,
            "wechat": {
                "enabled": True,
                "send_key": "SCT-test-key",
            },
        },
        logging.getLogger("test.notifier.circuit"),
        FakeMetrics(),
    )
    fallbacks = []
    monkeypatch.setattr(
        notifier_module.notification_transports,
        "send_serverchan",
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr(
        notifier,
        "_send_email",
        lambda message, level: fallbacks.append((message, level)) or True,
    )

    try:
        assert notifier._send_wechat("first", "CRITICAL") is False
        assert notifier._wechat_circuit_enabled is True
        assert notifier._send_wechat("second", "CRITICAL") is False
        assert notifier._wechat_circuit_enabled is False
        assert fallbacks == [("微信推送熔断已触发！失败次数: 2", "CRITICAL")]
    finally:
        notifier._stop_alert_worker()
