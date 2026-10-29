# sanitizer (benchmark case)

User-comment sanitizing written against `bleach==3.2.1`, which has 3 OSV advisories (mutation XSS, for example CVE-2021-23980).
Fixing them needs bleach 6.x, which removed the `styles=` argument in favour of `css_sanitizer=`.
