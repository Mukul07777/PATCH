from mailer import render


def test_welcome_renders():
    out = render.render_welcome("Ada", "Thanks for joining")
    assert "<p>Hi Ada,</p>" in out
    assert "<em>Thanks for joining</em>" in out


def test_signature_uses_context():
    out = render.render_welcome("Ada", "x", company="Acme")
    assert "&mdash; Team at Acme" in out


def test_name_is_escaped():
    out = render.render_welcome("<script>", "x")
    assert "<script>" not in out and "&lt;script&gt;" in out


def test_intro_is_escaped_inside_em():
    out = render.render_welcome("Ada", "<b>bold</b>")
    assert "<em>&lt;b&gt;bold&lt;/b&gt;</em>" in out
