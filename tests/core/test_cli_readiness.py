def test_service_ready_requires_successful_health_response(monkeypatch):
    from anteumbra.cli import main

    seen = {}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def urlopen(url, timeout):
        seen["url"] = url
        seen["timeout"] = timeout
        return Response()

    monkeypatch.setattr(main.urlrequest, "urlopen", urlopen)

    assert main._service_ready("0.0.0.0", 18080, timeout=0.5) is True
    assert seen == {
        "url": "http://127.0.0.1:18080/api/v1/health",
        "timeout": 0.5,
    }


def test_service_ready_rejects_connection_failures(monkeypatch):
    from anteumbra.cli import main

    def urlopen(*_args, **_kwargs):
        raise main.urlerror.URLError("not ready")

    monkeypatch.setattr(main.urlrequest, "urlopen", urlopen)

    assert main._service_ready("127.0.0.1", 18080) is False
