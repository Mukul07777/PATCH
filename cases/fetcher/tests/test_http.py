from fetcher import http


def test_retry_allows_post():
    r = http.build_retry()
    assert r.total == 3
    assert r.is_retry("POST", 503)
    assert not r.is_retry("POST", 404)


def test_retry_allows_get():
    assert http.build_retry().is_retry("GET", 502)


def test_pool_uses_retry():
    pool = http.build_pool(total=5)
    assert pool.connection_pool_kw["retries"].total == 5


def test_response_headers_lowercased():
    resp = http.fake_response(headers={"Content-Type": "application/json; charset=utf-8", "X-Req": "1"})
    assert http.response_headers(resp) == {"content-type": "application/json; charset=utf-8", "x-req": "1"}


def test_content_type():
    resp = http.fake_response(headers={"Content-Type": "text/html; charset=utf-8"})
    assert http.content_type(resp) == "text/html"


def test_missing_content_type():
    assert http.content_type(http.fake_response()) == ""
