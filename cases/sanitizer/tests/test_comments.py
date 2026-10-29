from sanitizer import comments


def test_script_removed():
    out = comments.clean_comment("hi <script>alert(1)</script><b>there</b>")
    assert "<script" not in out and "<b>there</b>" in out


def test_href_kept_onclick_dropped():
    out = comments.clean_comment('<a href="https://x.dev" onclick="evil()">x</a>')
    assert 'href="https://x.dev"' in out and "onclick" not in out


def test_allowed_style_kept():
    out = comments.clean_comment('<span style="color: red; position: fixed">hey</span>')
    assert "color: red" in out
    assert "position" not in out


def test_linkify():
    assert 'href="http://example.com"' in comments.linkify_comment("see http://example.com")


def test_plain_text():
    assert comments.plain_text("<p>a <b>b</b></p>") == "a b"
