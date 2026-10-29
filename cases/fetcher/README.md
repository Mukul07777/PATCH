# fetcher (benchmark case)

An HTTP helper written against `urllib3==1.26.17`, which has 9 OSV advisories (for example CVE-2023-45803, request body kept on 303 redirect).
Fixing them needs urllib3 2.x, which removed `Retry(method_whitelist=...)`, `Retry.DEFAULT_METHOD_WHITELIST` and `HTTPResponse.getheaders()`.
