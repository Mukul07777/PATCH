# mailer (benchmark case)

Email templating written against `Jinja2==2.11.3`, which has 4 OSV advisories (sandbox breakout and xmlattr injection, for example CVE-2024-22195 and CVE-2025-27516).
Fixing them needs Jinja2 3.1.x, which removed `jinja2.Markup`, `jinja2.escape` and `@contextfilter` (replaced by `markupsafe` and `@pass_context`).
