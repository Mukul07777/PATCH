from patchpilot.intel import sources


def test_vkey_and_version_gte():
    assert sources.version_gte("2.10.0", "2.9.9")
    assert sources.version_gte("1.7.1", "1.7.1")
    assert not sources.version_gte("1.7.1", "2.4.0")
    assert sources._vkey("1.0") < sources._vkey("1.0.1")


def test_min_safe_version():
    vulns = [{"fixed": ["2.4.0", "1.7.0"]}, {"fixed": ["2.2.3"]}]
    assert sources.min_safe_version("1.7.1", vulns) == "2.4.0"
    assert sources.min_safe_version("2.0.3", [{"fixed": ["1.0.0", "2.2.3", "2.3.0"]}]) == "2.2.3"
    assert sources.min_safe_version("3.0.0", vulns) is None
    assert sources.min_safe_version("1.0", []) is None
