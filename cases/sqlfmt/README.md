# sqlfmt (benchmark case)

A SQL formatter for query logs written against `sqlparse==0.4.1`, which has 9 OSV advisories (ReDoS and recursion DoS, for example CVE-2023-30608 and CVE-2024-4340).
This is the control case: the upgrade is expected to need no code changes.
