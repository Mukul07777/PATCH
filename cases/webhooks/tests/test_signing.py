from hooksvc import signing


def test_sign_and_verify():
    body = b'{"event":"paid"}'
    assert signing.verify(body, signing.sign(body))


def test_verify_rejects_tampering():
    assert not signing.verify(b'{"event":"paid"}', signing.sign(b'{"event":"refund"}'))


def test_callback_url_quotes_event_and_sorts_params():
    url = signing.callback_url("https://api.example.com/", "invoice paid", {"b": "2", "a": "x y"})
    assert url == "https://api.example.com/hooks/invoice%20paid?a=x+y&b=2"


def test_api_key_hashing():
    h = signing.hash_api_key("sk_live_123")
    assert h != "sk_live_123"
    assert signing.check_api_key(h, "sk_live_123")
    assert not signing.check_api_key(h, "nope")
